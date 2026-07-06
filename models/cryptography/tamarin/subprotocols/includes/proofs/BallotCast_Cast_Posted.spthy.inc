simplify
solve( DBB_State_ConfirmCastPosting( ~ec, ~va_id, ~cid, pseudo,
                                     sub_tracker, bbe_c
       ) ▶₀ #i )
  case BallotCast_DBB_AppendCastBallot_case_2
  solve( !BB_Root( ~ec, ~bbid, r_unused, root_eid_unused ) ▶₁ #i )
    case BulletinBoard_Create
    solve( !BB_Entry( ~bbid, ~cast_tracker,
                      <'BBEntry_Ballot_Cast', ~ts,
                       <
                        <'VA_Submit_Ballot', ~ec, cryptograms,
                         <'VoterAuthorization', ~ec, pseudo, pk_voter, ballot_style, ts.1>,
                         sign(<'VoterAuthorization', ~ec, pseudo, pk_voter, ballot_style, ts.1>,
                              x, ~sk_eas)
                        >,
                        sig_submit>,
                       <'VA_Cast_Ballot', ~ec, ~new_eid,
                        <'VoterAuthorization', ~ec, pseudo, pk_voter, ballot_style, ts.1>,
                        sign(<'VoterAuthorization', ~ec, pseudo, pk_voter, ballot_style, ts.1>,
                             x, ~sk_eas)
                       >,
                       sig_cast>,
                      prev_unused
           ) ▶₂ #i )
      case BulletinBoard_Append
      solve( BB_Trace_Entry( ~bbid, ~new_eid,
                             <'BBEntry_Ballot_Submission', ~ec, ts_sub,
                              <'VA_Submit_Ballot', ~ec, cryptograms,
                               <'VoterAuthorization', ~ec, pseudo, pk_voter, ballot_style, ts.1>,
                               sign(<'VoterAuthorization', ~ec, pseudo, pk_voter, ballot_style, ts.1>,
                                    x, ~sk_eas)
                              >,
                              sig_submit>,
                             prev_unused.1
             ) @ #vr.5 )
        case BulletinBoard_Append
        solve( splitEqs(5) )
          case split_case_2
          solve( SecureReceive( ~cid, ~va_id, <~ec, 'DBB'>,
                                <
                                 <'VA_Cast_Ballot', ~ec, ~new_eid,
                                  <'VoterAuthorization', ~ec, pseudo, pk_voter, ballot_style, ts.1>,
                                  sign(<'VoterAuthorization', ~ec, pseudo, pk_voter, ballot_style, ts.1>,
                                       x, ~sk_eas)
                                 >,
                                 sign(z, x.1, z.1)>
                 ) ▶₃ #vr.1 )
            case SecureChannel_Receive_case_1
            solve( BB_Current( ~bbid, prev_prev_unused ) ▶₁ #vr.3 )
              case BulletinBoard_Create
              solve( BB_Append_Request( ~bbid, e_unused, ~root_eid ) ▶₂ #vr.3 )
                case Mock_AppendSubmittedBallot
                solve( (~new_eid.1 = ~new_eid)  ∥ (¬(#vr.5 < #vr.3))  ∥
                       (¬(#vr.3 < #vr.1)) )
                  case case_1
                  solve( BB_Current( ~bbid, prev_unused ) ▶₁ #vr.7 )
                    case BulletinBoard_Append
                    solve( BB_Append_Request( ~bbid,
                                              <'BBEntry_Ballot_Cast', ~ts,
                                               <
                                                <'VA_Submit_Ballot', ~ec,
                                                 <ny_encrypt_c1(~ballot, pk(~sk_election), ~r),
                                                  ny_encrypt_c2(~ballot, pk(~sk_election), ~r),
                                                  ny_encrypt_p(~ballot, pk(~sk_election), ~r)>,
                                                 <'VoterAuthorization', ~ec, pseudonym($V), pk(~sk_voter),
                                                  ~ballot_style, ~ts.1>,
                                                 sign(<'VoterAuthorization', ~ec, pseudonym($V),
                                                       pk(~sk_voter), ~ballot_style, ~ts.1>,
                                                      '1', ~sk_eas)
                                                >,
                                                sign(<'VA_Submit_Ballot', ~ec,
                                                      <ny_encrypt_c1(~ballot, pk(~sk_election), ~r),
                                                       ny_encrypt_c2(~ballot, pk(~sk_election), ~r),
                                                       ny_encrypt_p(~ballot, pk(~sk_election), ~r)>,
                                                      <'VoterAuthorization', ~ec, pseudonym($V),
                                                       pk(~sk_voter), ~ballot_style, ~ts.1>,
                                                      sign(<'VoterAuthorization', ~ec, pseudonym($V),
                                                            pk(~sk_voter), ~ballot_style, ~ts.1>,
                                                           '1', ~sk_eas)
                                                     >,
                                                     '1', ~sk_voter)
                                               >,
                                               <'VA_Cast_Ballot', ~ec, ~new_eid,
                                                <'VoterAuthorization', ~ec, pseudonym($V), pk(~sk_voter),
                                                 ~ballot_style, ~ts.1>,
                                                sign(<'VoterAuthorization', ~ec, pseudonym($V),
                                                      pk(~sk_voter), ~ballot_style, ~ts.1>,
                                                     '1', ~sk_eas)
                                               >,
                                               sign(<'VA_Cast_Ballot', ~ec, ~new_eid,
                                                     <'VoterAuthorization', ~ec, pseudonym($V),
                                                      pk(~sk_voter), ~ballot_style, ~ts.1>,
                                                     sign(<'VoterAuthorization', ~ec, pseudonym($V),
                                                           pk(~sk_voter), ~ballot_style, ~ts.1>,
                                                          '1', ~sk_eas)
                                                    >,
                                                    '1', ~sk_voter)
                                              >,
                                              ~new_eid.1
                           ) ▶₂ #vr.7 )
                      case BallotCast_DBB_AppendCastBallot
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
