simplify
solve( VA_State_RequestRandomizers( ~ec, ~va_id, $V, p, ~ballot, c, ~r, t
       ) ▶₀ #i )
  case BallotCheck_VA_Check_case_1
  solve( BB_Append_Request( ~bbid,
                            <'BBEntry_Ballot_Submission', ~ec, ~ts.1,
                             <'VA_Submit_Ballot', ~ec,
                              <ny_encrypt_c1(~ballot, pk(~sk_election), ~r),
                               ny_encrypt_c2(~ballot, pk(~sk_election), ~r),
                               ny_encrypt_p(~ballot, pk(~sk_election), ~r)>,
                              <'VoterAuthorization', ~ec, pseudonym($V), pk(~sk_voter.1),
                               ~ballot_style.1, ~ts>,
                              sign(<'VoterAuthorization', ~ec, pseudonym($V), pk(~sk_voter.1),
                                    ~ballot_style.1, ~ts>,
                                   '1', ~sk_eas)
                             >,
                             sign(<'VA_Submit_Ballot', ~ec,
                                   <ny_encrypt_c1(~ballot, pk(~sk_election), ~r),
                                    ny_encrypt_c2(~ballot, pk(~sk_election), ~r),
                                    ny_encrypt_p(~ballot, pk(~sk_election), ~r)>,
                                   <'VoterAuthorization', ~ec, pseudonym($V), pk(~sk_voter.1),
                                    ~ballot_style.1, ~ts>,
                                   sign(<'VoterAuthorization', ~ec, pseudonym($V), pk(~sk_voter.1),
                                         ~ballot_style.1, ~ts>,
                                        '1', ~sk_eas)
                                  >,
                                  '1', ~sk_voter.1)
                            >,
                            prev_unused
         ) ▶₂ #vr.6 )
    case Mock_AppendSubmittedBallot
    solve( BB_Current( ~bbid, ~root_eid ) ▶₁ #vr.6 )
      case BulletinBoard_Create
      solve( !VA_Eligible_Voter( ~ec, ~va_id, pseudonym($V), ~sk_voter,
                                 ~ballot_style, signed_voter_auth_unused
             ) ▶₁ #i )
        case Mock_Voter_Authentication
        solve( SecureReceive( ~cid, <~ec, 'DBB'>, ~va_id,
                              <'DBB_Check_Request',
                               <'BCA_Check_Request', ~ec, ~tracker, pk, pk_bca_sign>, sig_bca_req>
               ) ▶₃ #i )
          case SecureChannel_Receive_case_1
          solve( SecureReceive( ~cid_bca, ~bca_id, <~ec, 'DBB'>,
                                <<'BCA_Check_Request', ~ec, ~tracker, pk(~sk_bca_encrypt), pk(~z)>,
                                 sign(<'BCA_Check_Request', ~ec, ~tracker, pk(~sk_bca_encrypt), pk(~z)>,
                                      '1', ~z)
                                >
                 ) ▶₃ #vr.12 )
            case SecureChannel_Receive_case_1
            SOLVED // trace found
          qed
        qed
      qed
    qed
  qed
qed
