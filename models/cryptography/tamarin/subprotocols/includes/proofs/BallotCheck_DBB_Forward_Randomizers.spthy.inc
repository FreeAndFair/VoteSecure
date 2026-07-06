simplify
solve( SecureReceive( ~cid_va, ~va_id, <~ec, 'DBB'>,
                      <
                       <'VA_Check_Randomizers',
                        <<'BCA_Check_Request', ~ec, tracker, pk_bca_encrypt, pk_bca_sign>,
                         sig_bca_req>,
                        encrypted_randomizers, pk_voter>,
                       sig_randomizers>
       ) ▶₁ #i )
  case SecureChannel_Receive_case_01
  solve( BB_Append_Request( ~bbid,
                            <'BBEntry_Ballot_Submission', ~ec, ~ts.1,
                             <'VA_Submit_Ballot', ~ec,
                              <ny_encrypt_c1(~ballot, pk(~sk_election), ~r),
                               ny_encrypt_c2(~ballot, pk(~sk_election), ~r),
                               ny_encrypt_p(~ballot, pk(~sk_election), ~r)>,
                              <'VoterAuthorization', ~ec, pseudonym($V), pk(~z.1), ~ballot_style, ~ts
                              >,
                              sign(<'VoterAuthorization', ~ec, pseudonym($V), pk(~z.1), ~ballot_style,
                                    ~ts>,
                                   '1', ~sk_eas)
                             >,
                             sign(<'VA_Submit_Ballot', ~ec,
                                   <ny_encrypt_c1(~ballot, pk(~sk_election), ~r),
                                    ny_encrypt_c2(~ballot, pk(~sk_election), ~r),
                                    ny_encrypt_p(~ballot, pk(~sk_election), ~r)>,
                                   <'VoterAuthorization', ~ec, pseudonym($V), pk(~z.1), ~ballot_style, ~ts
                                   >,
                                   sign(<'VoterAuthorization', ~ec, pseudonym($V), pk(~z.1), ~ballot_style,
                                         ~ts>,
                                        '1', ~sk_eas)
                                  >,
                                  '1', ~z.1)
                            >,
                            prev_unused
         ) ▶₂ #vr.10 )
    case Mock_AppendSubmittedBallot
    solve( BB_Current( ~bbid, ~root_eid ) ▶₁ #vr.10 )
      case BulletinBoard_Create
      solve( SecureReceive( ~cid_va, <~ec, 'DBB'>, ~va_id,
                            <'DBB_Check_Request',
                             <'BCA_Check_Request', ~ec, ~tracker, pk(~sk_bca_encrypt), pk(~z)>,
                             sign(<'BCA_Check_Request', ~ec, ~tracker, pk(~sk_bca_encrypt), pk(~z)>,
                                  '1', ~z)
                            >
             ) ▶₃ #vr.2 )
        case SecureChannel_Receive_case_1
        solve( SecureReceive( ~cid_bca.1, ~bca_id.1, <~ec, 'DBB'>,
                              <<'BCA_Check_Request', ~ec, ~tracker, pk(~sk_bca_encrypt), pk(~z)>,
                               sign(<'BCA_Check_Request', ~ec, ~tracker, pk(~sk_bca_encrypt), pk(~z)>,
                                    '1', ~z)
                              >
               ) ▶₃ #vr.14 )
          case SecureChannel_Receive_case_1
          solve( SecureReceive( ~cid_bca.1, ~bca_id.1, <~ec, 'DBB'>,
                                <<'BCA_Check_Request', ~ec, ~tracker, pk(~sk_bca_encrypt), pk(~z)>,
                                 sign(<'BCA_Check_Request', ~ec, ~tracker, pk(~sk_bca_encrypt), pk(~z)>,
                                      '1', ~z)
                                >
                 ) ▶₃ #vr.19 )
            case SecureChannel_Receive_case_1
            solve( DBB_State_ForwardRandomizers( ~ec, ~va_id, ~cid_va, ~bca_id,
                                                 ~cid_bca,
                                                 <
                                                  <'BCA_Check_Request', ~ec, ~tracker, pk(~sk_bca_encrypt),
                                                   pk(~z)>,
                                                  sign(<'BCA_Check_Request', ~ec, ~tracker,
                                                        pk(~sk_bca_encrypt), pk(~z)>,
                                                       '1', ~z)
                                                 >
                   ) ▶₀ #i )
              case BallotCheck_DBB_ReceiveCheckRequest_case_1
              solve( SecureReceive( ~cid_bca, ~bca_id, <~ec, 'DBB'>,
                                    <<'BCA_Check_Request', ~ec, ~tracker, pk(~sk_bca_encrypt), pk(~z)>,
                                     sign(<'BCA_Check_Request', ~ec, ~tracker, pk(~sk_bca_encrypt), pk(~z)>,
                                          '1', ~z)
                                    >
                     ) ▶₃ #vr.17 )
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
