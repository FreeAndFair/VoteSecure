simplify
solve( BB_Trace_Entry( ~bbid, tracker,
                       <'BBEntry_Ballot_Submission', ec.6, ts.1,
                        <'VA_Submit_Ballot', ec.6, c,
                         <'VoterAuthorization', ec.6, pseudo, pk, bs.1, auth_ts>, auth_sig>,
                        sig>,
                       prev
       ) @ #j )
  case BulletinBoard_Append
  solve( !BB_Root( ~ec, ~bbid, r_unused, root_eid_unused ) ▶₁ #i )
    case BulletinBoard_Create
    solve( !BB_Root( reqid, ~bbid, r, root_eid.1 ) ▶₀ #j )
      case BulletinBoard_Create
      solve( !BB_Entry( ~bbid, ~new_eid,
                        <'BBEntry_Ballot_Submission', ~ec, ts_sub,
                         <'VA_Submit_Ballot', ~ec, cryptograms,
                          <'VoterAuthorization', ~ec, pseudo, pk_voter, ballot_style, ts>, sig_auth
                         >,
                         sig_submit>,
                        prev_unused
             ) ▶₂ #i )
        case BulletinBoard_Append
        solve( BB_Append_Request( ~bbid,
                                  <'BBEntry_Ballot_Submission', ~ec, ts_sub,
                                   <'VA_Submit_Ballot', ~ec, c,
                                    <'VoterAuthorization', ~ec, pseudo, pk, ballot_style, auth_ts>, auth_sig
                                   >,
                                   sig>,
                                  prev
               ) ▶₂ #j )
          case Mock_AppendSubmittedBallot_case_1
          solve( BB_Current( ~bbid, ~root_eid ) ▶₁ #j )
            case BulletinBoard_Create
            solve( SecureReceive( ~cid, ~va_id, <~ec, 'DBB'>,
                                  <
                                   <'VA_Cast_Ballot', ~ec, ~new_eid,
                                    <'VoterAuthorization', ~ec, pseudonym($V), pk(~sk_voter), ~ballot_style,
                                     ~ts.1>,
                                    sign(<'VoterAuthorization', ~ec, pseudonym($V), pk(~sk_voter),
                                          ~ballot_style, ~ts.1>,
                                         '1', ~sk_eas)
                                   >,
                                   sign(<'VA_Cast_Ballot', ~ec, ~new_eid,
                                         <'VoterAuthorization', ~ec, pseudonym($V), pk(~sk_voter),
                                          ~ballot_style, ~ts.1>,
                                         sign(<'VoterAuthorization', ~ec, pseudonym($V), pk(~sk_voter),
                                               ~ballot_style, ~ts.1>,
                                              '1', ~sk_eas)
                                        >,
                                        x, ~sk_voter)
                                  >
                   ) ▶₃ #i )
              case SecureChannel_Receive_case_1
              solve( !EASPublicKey( ~ec, pk_eas ) ▶₀ #i )
                case Mock_Finalize_Election_Setup
                SOLVED // trace found
              qed
            qed
          qed
        qed
      qed
    qed
  qed
qed
