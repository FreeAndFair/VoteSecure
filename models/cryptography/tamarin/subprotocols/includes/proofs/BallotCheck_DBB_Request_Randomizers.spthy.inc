simplify
solve( !BB_Root( ~ec, ~bbid, r_unused, root_eid_unused ) ▶₀ #i )
  case BulletinBoard_Create
  solve( !BB_Entry( ~bbid, tracker,
                    <'BBEntry_Ballot_Submission', ~ec, timestamp, signed_msg_submit_ballot>,
                    prev_unused
         ) ▶₁ #i )
    case BulletinBoard_Append
    solve( BB_Append_Request( ~bbid,
                              <'BBEntry_Ballot_Submission', ~ec, timestamp, signed_msg_submit_ballot>,
                              prev_unused
           ) ▶₂ #vr.4 )
      case Mock_AppendSubmittedBallot_case_1
      solve( BB_Current( ~bbid, ~root_eid ) ▶₁ #vr.4 )
        case BulletinBoard_Create
        solve( SecureReceive( ~cid_bca, ~bca_id, <~ec, 'DBB'>,
                              <<'BCA_Check_Request', ~ec, ~new_eid, pk_bca_encrypt, pk_bca_sign>,
                               sig_bca_req>
               ) ▶₃ #i )
          case SecureChannel_Receive_case_1
          solve( !DBB_Submitted_Ballot( ~ec, ~va_id, ~cid_va, pseudo,
                                        <
                                         <'VA_Submit_Ballot', ~ec,
                                          <ny_encrypt_c1(~ballot, pk(~sk_election), ~r),
                                           ny_encrypt_c2(~ballot, pk(~sk_election), ~r),
                                           ny_encrypt_p(~ballot, pk(~sk_election), ~r)>,
                                          <'VoterAuthorization', ~ec, pseudonym($V), pk(~sk_voter),
                                           ~ballot_style, ~ts.1>,
                                          sign(<'VoterAuthorization', ~ec, pseudonym($V), pk(~sk_voter),
                                                ~ballot_style, ~ts.1>,
                                               '1', ~sk_eas)
                                         >,
                                         sign(<'VA_Submit_Ballot', ~ec,
                                               <ny_encrypt_c1(~ballot, pk(~sk_election), ~r),
                                                ny_encrypt_c2(~ballot, pk(~sk_election), ~r),
                                                ny_encrypt_p(~ballot, pk(~sk_election), ~r)>,
                                               <'VoterAuthorization', ~ec, pseudonym($V), pk(~sk_voter),
                                                ~ballot_style, ~ts.1>,
                                               sign(<'VoterAuthorization', ~ec, pseudonym($V), pk(~sk_voter),
                                                     ~ballot_style, ~ts.1>,
                                                    '1', ~sk_eas)
                                              >,
                                              '1', ~sk_voter)
                                        >
                 ) ▶₂ #i )
            case Mock_Ballot_Submission
            SOLVED // trace found
          qed
        qed
      qed
    qed
  qed
qed
