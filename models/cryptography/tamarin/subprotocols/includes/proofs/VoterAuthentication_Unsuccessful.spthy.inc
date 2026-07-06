simplify
solve( SecureReceive( ~cid, requesting_eas, 'AS',
                      <'EAS_Request_Authentication_Result', ~session_id>
       ) ▶₁ #i )
  case SecureChannel_Receive_case_1
  solve( SecureReceive( ~cid_va, ~va_id, <~ec, 'EAS'>,
                        <'VA_Authentication_Complete', ~ec, pk(~sk_voter), ~token>
         ) ▶₁ #vr.2 )
    case SecureChannel_Receive_case_1
    solve( SecureReceive( ~cid_as, 'AS', <~ec, 'EAS'>,
                          <'AS_Authentication_Session', ~session_id, ~token>
           ) ▶₁ #vr.3 )
      case SecureChannel_Receive_case_1
      solve( SecureReceive( ~cid_va.1, ~va_id, <~ec, 'EAS'>,
                            <'VA_Request_Authentication', ~ec, pk(~sk_voter)>
             ) ▶₂ #vr.4 )
        case SecureChannel_Receive_case_1
        solve( SecureReceive( ~cid_as.1, 'AS', ~va_id,
                              <'AS_Authentication_Complete', ~token>
               ) ▶₂ #vr.17 )
          case SecureChannel_Receive_case_4
          solve( SecureReceive( ~cid_va.1, <~ec, 'EAS'>, ~va_id,
                                <'EAS_Authentication_Session', ~ec, pk(~sk_voter), ~token>
                 ) ▶₂ #vr.19 )
            case SecureChannel_Receive_case_1
            solve( SecureReceive( ~cid_as, <~ec, 'EAS'>, 'AS',
                                  <'EAS_Request_Authentication_Session', ~project_id, ~api_key>
                   ) ▶₁ #vr.22 )
              case SecureChannel_Receive_case_1
              solve( SecureReceive( ~cid_as.1, ~va_id, 'AS',
                                    <'Voter_Authentication', ~token, $voter_id.1>
                     ) ▶₁ #vr.26 )
                case SecureChannel_Receive_case_1
                solve( SecureReceive( ~cid_as.2, 'AS', <~ec, 'EAS'>,
                                      <'AS_Authentication_Session', ~session_id.1, ~token>
                       ) ▶₁ #vr.29 )
                  case SecureChannel_Receive_case_1
                  solve( EAS_ReceiveAuthenticationResult_Trace( ~session_id,
                                                                'unsuccessful', 'ineligible', 'ineligible'
                         ) @ #j.3 )
                    case VoterAuthentication_EAS_ReceiveAuthenticationResult_Unsuccessful
                    solve( SecureReceive( ~cid_as.1, 'AS', <~ec.1, 'EAS'>,
                                          <'AS_Authentication_Result', ~session_id, $voter_id.1,
                                           'unsuccessful'>
                           ) ▶₁ #j.3 )
                      case SecureChannel_Receive_case_01
                      solve( SecureReceive( ~cid_as.1, <~ec, 'EAS'>, 'AS',
                                            <'EAS_Request_Authentication_Result', ~session_id>
                             ) ▶₁ #vr.33 )
                        case SecureChannel_Receive_case_1
                        solve( SecureReceive( ~cid_va, ~va_id, <~ec, 'EAS'>,
                                              <'VA_Authentication_Complete', ~ec, pk(~sk_voter), ~token>
                               ) ▶₁ #vr.35 )
                          case SecureChannel_Receive_case_1
                          solve( VA_ReceiveAuthenticationResult_Trace( ~ec, ~va_id, 'unsuccessful',
                                                                       'ineligible', pk(~sk_voter),
                                                                       'ineligible'
                                 ) @ #k )
                            case VoterAuthentication_VA_ReceiveAuthenticationResult_Unsuccessful
                            solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                                         ~sk_voter, ~cid.1, ~token.1
                                   ) ▶₀ #k )
                              case VoterAuthentication_VA_ReceiveAuthenticationComplete
                              solve( SecureReceive( ~cid_va, <~ec, 'EAS'>, ~va_id,
                                                    <'EAS_Authentication_Result', 'unsuccessful', ~ec,
                                                     pk(~sk_voter), 'ineligible'>
                                     ) ▶₁ #k )
                                case SecureChannel_Receive_case_1
                                solve( SecureReceive( ~cid_as.2, 'AS', <~ec, 'EAS'>,
                                                      <'AS_Authentication_Result', ~session_id.1, $voter_id,
                                                       'unsuccessful'>
                                       ) ▶₁ #vr.35 )
                                  case SecureChannel_Receive_case_01
                                  solve( SecureReceive( ~cid_va, ~va_id, <~ec, 'EAS'>,
                                                        <'VA_Authentication_Complete', ~ec, pk(~sk_voter),
                                                         ~token>
                                         ) ▶₁ #vr.36 )
                                    case SecureChannel_Receive_case_1
                                    solve( SecureReceive( ~cid, <~ec, 'EAS'>, 'AS',
                                                          <'EAS_Request_Authentication_Result', ~session_id>
                                           ) ▶₁ #vr.38 )
                                      case SecureChannel_Receive_case_1
                                      solve( (∃ #j.
                                               (AS_SuccessfulAuthentication_Trace( ~session_id ) @ #j)
                                              ∧
                                               #j < #i)  ∥
                                             (∃ #j.
                                               (AS_UnsuccessfulAuthentication_Trace( ~session_id ) @ #j)
                                              ∧
                                               #j < #i) )
                                        case case_2
                                        solve( SecureReceive( ~cid.1, ~v_id, 'AS',
                                                              <'Voter_Authentication', ~token.1, $voter_id>
                                               ) ▶₁ #j.4 )
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
            qed
          qed
        qed
      qed
    qed
  qed
qed
