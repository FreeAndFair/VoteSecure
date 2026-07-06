simplify
solve( SecureReceive( ~cid, <~ec, 'DBB'>, ~bca_id,
                      <'DBB_Check_Randomizers', ~ec,
                       <'VA_Check_Randomizers',
                        <<'BCA_Check_Request', ~ec, t, pk(~sk_bca_encrypt), pk(~sk_bca_sign)>,
                         sign(<'BCA_Check_Request', ~ec, t, pk(~sk_bca_encrypt), pk(~sk_bca_sign)
                              >,
                              '1', ~sk_bca_sign)
                        >,
                        <ny_encrypt_c1(x, x.1, x.2), ny_encrypt_c2(x, x.1, x.2),
                         ny_encrypt_p(x, x.1, x.2)>,
                        pk_voter>,
                       sig_randomizers>
       ) ▶₂ #i )
  case SecureChannel_Receive_case_01
  solve( BB_Append_Request( ~bbid,
                            <'BBEntry_Ballot_Submission', ~ec, ~ts.1,
                             <'VA_Submit_Ballot', ~ec,
                              <ny_encrypt_c1(~ballot.1, pk(~sk_election), ~r),
                               ny_encrypt_c2(~ballot.1, pk(~sk_election), ~r),
                               ny_encrypt_p(~ballot.1, pk(~sk_election), ~r)>,
                              <'VoterAuthorization', ~ec, pseudonym($V), pk(~sk_voter),
                               ~ballot_style.1, ~ts.2>,
                              sign(<'VoterAuthorization', ~ec, pseudonym($V), pk(~sk_voter),
                                    ~ballot_style.1, ~ts.2>,
                                   '1', ~sk_eas)
                             >,
                             sign(<'VA_Submit_Ballot', ~ec,
                                   <ny_encrypt_c1(~ballot.1, pk(~sk_election), ~r),
                                    ny_encrypt_c2(~ballot.1, pk(~sk_election), ~r),
                                    ny_encrypt_p(~ballot.1, pk(~sk_election), ~r)>,
                                   <'VoterAuthorization', ~ec, pseudonym($V), pk(~sk_voter),
                                    ~ballot_style.1, ~ts.2>,
                                   sign(<'VoterAuthorization', ~ec, pseudonym($V), pk(~sk_voter),
                                         ~ballot_style.1, ~ts.2>,
                                        '1', ~sk_eas)
                                  >,
                                  '1', ~sk_voter)
                            >,
                            prev_unused
         ) ▶₂ #vr.5 )
    case Mock_AppendSubmittedBallot
    solve( BB_Current( ~bbid, ~root_eid ) ▶₁ #vr.5 )
      case BulletinBoard_Create
      solve( SecureReceive( ~cid_va, ~va_id, <~ec, 'DBB'>,
                            <
                             <'VA_Check_Randomizers',
                              <
                               <'BCA_Check_Request', ~ec, ~new_eid, pk(~sk_bca_encrypt),
                                pk(~sk_bca_sign)>,
                               sign(<'BCA_Check_Request', ~ec, ~new_eid, pk(~sk_bca_encrypt),
                                     pk(~sk_bca_sign)>,
                                    '1', ~sk_bca_sign)
                              >,
                              <ny_encrypt_c1(~r, pk(~sk_bca_encrypt), ~throwaway_r),
                               ny_encrypt_c2(~r, pk(~sk_bca_encrypt), ~throwaway_r),
                               ny_encrypt_p(~r, pk(~sk_bca_encrypt), ~throwaway_r)>,
                              pk(~sk_voter)>,
                             sign(<'VA_Check_Randomizers',
                                   <
                                    <'BCA_Check_Request', ~ec, ~new_eid, pk(~sk_bca_encrypt),
                                     pk(~sk_bca_sign)>,
                                    sign(<'BCA_Check_Request', ~ec, ~new_eid, pk(~sk_bca_encrypt),
                                          pk(~sk_bca_sign)>,
                                         '1', ~sk_bca_sign)
                                   >,
                                   <ny_encrypt_c1(~r, pk(~sk_bca_encrypt), ~throwaway_r),
                                    ny_encrypt_c2(~r, pk(~sk_bca_encrypt), ~throwaway_r),
                                    ny_encrypt_p(~r, pk(~sk_bca_encrypt), ~throwaway_r)>,
                                   pk(~sk_voter)>,
                                  '1', ~sk_voter)
                            >
             ) ▶₁ #vr.2 )
        case SecureChannel_Receive_case_1
        solve( SecureReceive( ~cid, ~bca_id, <~ec, 'DBB'>,
                              <
                               <'BCA_Check_Request', ~ec, ~new_eid, pk(~sk_bca_encrypt),
                                pk(~sk_bca_sign)>,
                               sign(<'BCA_Check_Request', ~ec, ~new_eid, pk(~sk_bca_encrypt),
                                     pk(~sk_bca_sign)>,
                                    '1', ~sk_bca_sign)
                              >
               ) ▶₃ #vr.3 )
          case SecureChannel_Receive_case_1
          solve( SecureReceive( ~cid_va, <~ec, 'DBB'>, ~va_id,
                                <'DBB_Check_Request',
                                 <'BCA_Check_Request', ~ec, ~new_eid, pk(~sk_bca_encrypt),
                                  pk(~sk_bca_sign)>,
                                 sign(<'BCA_Check_Request', ~ec, ~new_eid, pk(~sk_bca_encrypt),
                                       pk(~sk_bca_sign)>,
                                      '1', ~sk_bca_sign)
                                >
                 ) ▶₃ #vr.13 )
            case SecureChannel_Receive_case_1
            solve( SecureReceive( ~cid, ~bca_id, <~ec, 'DBB'>,
                                  <
                                   <'BCA_Check_Request', ~ec, ~new_eid, pk(~sk_bca_encrypt),
                                    pk(~sk_bca_sign)>,
                                   sign(<'BCA_Check_Request', ~ec, ~new_eid, pk(~sk_bca_encrypt),
                                         pk(~sk_bca_sign)>,
                                        '1', ~sk_bca_sign)
                                  >
                   ) ▶₃ #vr.18 )
              case SecureChannel_Receive_case_1
              solve( SecureReceive( ~cid, ~bca_id, <~ec, 'DBB'>,
                                    <
                                     <'BCA_Check_Request', ~ec, ~new_eid, pk(~sk_bca_encrypt),
                                      pk(~sk_bca_sign)>,
                                     sign(<'BCA_Check_Request', ~ec, ~new_eid, pk(~sk_bca_encrypt),
                                           pk(~sk_bca_sign)>,
                                          '1', ~sk_bca_sign)
                                    >
                     ) ▶₃ #vr.20 )
                case SecureChannel_Receive_case_1
                solve( SecureReceive( ~cid, ~bca_id, <~ec, 'DBB'>,
                                      <
                                       <'BCA_Check_Request', ~ec, ~new_eid, pk(~sk_bca_encrypt),
                                        pk(~sk_bca_sign)>,
                                       sign(<'BCA_Check_Request', ~ec, ~new_eid, pk(~sk_bca_encrypt),
                                             pk(~sk_bca_sign)>,
                                            '1', ~sk_bca_sign)
                                      >
                       ) ▶₃ #vr.21 )
                  case SecureChannel_Receive_case_1
                  solve( BCA_State_AwaitRandomizers( ~ec, ~new_eid, ~bca_id, ~cid,
                                                     ~sk_bca_encrypt, ~sk_bca_sign,
                                                     <'BBEntry_Ballot_Submission', ~ec, timestamp,
                                                      <'VA_Submit_Ballot', ~ec,
                                                       <ny_encrypt_c1(~ballot, pk_election, ~r),
                                                        ny_encrypt_c2(~ballot, pk_election, ~r),
                                                        ny_encrypt_p(~ballot, pk_election, ~r)>,
                                                       <'VoterAuthorization', ~ec, pseudo, pk(~sk_voter),
                                                        ballot_style, ts>,
                                                       sig_auth>,
                                                      sig_msg_submit_ballot>
                         ) ▶₀ #i )
                    case BallotCheck_BCA_InitiateBallotCheck
                    solve( !ElectionPublicKey( ~ec, pk(~sk_election) ) ▶₁ #i )
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
    qed
  qed
qed
