simplify
solve( (¬(res1 = res2))  ∥ (¬(pseudo1 = pseudo2))  ∥ (¬(pk1 = pk2))  ∥
       (¬(bs1 = bs2))  ∥ (¬(#i1 = #i2)) )
  case case_1
  solve( VA_ReceiveAuthenticationResult_Trace( ec, va_id, res1, pseudo1,
                                               pk1, bs1
         ) @ #i1 )
    case VoterAuthentication_VA_ReceiveAuthenticationResult_Eligible
    solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V, ~sk_voter,
                                                 ~cid, ~token
           ) ▶₀ #i1 )
      case VoterAuthentication_VA_ReceiveAuthenticationComplete
      solve( SecureReceive( ~cid, <~ec, 'EAS'>, ~va_id,
                            <'EAS_Authentication_Result', 'eligible', ~ec, pk(~sk_voter),
                             <'VoterAuthorization', ~ec, pseudo1, pk(~sk_voter), bs1, ts>, sig_auth>
             ) ▶₁ #i1 )
        case SecureChannel_Receive_case_1
        solve( VA_ReceiveAuthenticationResult_Trace( ~ec, ~va_id, res2, pseudo2,
                                                     pk2, bs2
               ) @ #i2 )
          case VoterAuthentication_VA_ReceiveAuthenticationResult_Eligible
          by contradiction /* from formulas */
        next
          case VoterAuthentication_VA_ReceiveAuthenticationResult_Ineligible
          by solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                          ~sk_voter.1, ~cid.1, ~token.1
                    ) ▶₀ #i2 )
        next
          case VoterAuthentication_VA_ReceiveAuthenticationResult_Unsuccessful
          by solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                          ~sk_voter.1, ~cid.1, ~token.1
                    ) ▶₀ #i2 )
        qed
      next
        case SecureChannel_Receive_case_2
        solve( VA_ReceiveAuthenticationResult_Trace( ~ec, ~va_id, res2, pseudo2,
                                                     pk2, bs2
               ) @ #i2 )
          case VoterAuthentication_VA_ReceiveAuthenticationResult_Eligible
          by contradiction /* from formulas */
        next
          case VoterAuthentication_VA_ReceiveAuthenticationResult_Ineligible
          by solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                          ~sk_voter.1, ~cid.1, ~token.1
                    ) ▶₀ #i2 )
        next
          case VoterAuthentication_VA_ReceiveAuthenticationResult_Unsuccessful
          by solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                          ~sk_voter.1, ~cid.1, ~token.1
                    ) ▶₀ #i2 )
        qed
      next
        case SecureChannel_Receive_case_3
        solve( VA_ReceiveAuthenticationResult_Trace( ~ec, ~va_id, res2, pseudo2,
                                                     pk2, bs2
               ) @ #i2 )
          case VoterAuthentication_VA_ReceiveAuthenticationResult_Eligible
          by contradiction /* from formulas */
        next
          case VoterAuthentication_VA_ReceiveAuthenticationResult_Ineligible
          by solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                          ~sk_voter.1, ~cid.1, ~token.1
                    ) ▶₀ #i2 )
        next
          case VoterAuthentication_VA_ReceiveAuthenticationResult_Unsuccessful
          by solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                          ~sk_voter.1, ~cid.1, ~token.1
                    ) ▶₀ #i2 )
        qed
      next
        case SecureChannel_Receive_case_4
        solve( VA_ReceiveAuthenticationResult_Trace( ~ec, ~va_id, res2, pseudo2,
                                                     pk2, bs2
               ) @ #i2 )
          case VoterAuthentication_VA_ReceiveAuthenticationResult_Eligible
          by contradiction /* from formulas */
        next
          case VoterAuthentication_VA_ReceiveAuthenticationResult_Ineligible
          by solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                          ~sk_voter.1, ~cid.1, ~token.1
                    ) ▶₀ #i2 )
        next
          case VoterAuthentication_VA_ReceiveAuthenticationResult_Unsuccessful
          by solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                          ~sk_voter.1, ~cid.1, ~token.1
                    ) ▶₀ #i2 )
        qed
      next
        case SecureChannel_Receive_case_5
        solve( VA_ReceiveAuthenticationResult_Trace( ~ec, ~va_id, res2, pseudo2,
                                                     pk2, bs2
               ) @ #i2 )
          case VoterAuthentication_VA_ReceiveAuthenticationResult_Eligible
          by contradiction /* from formulas */
        next
          case VoterAuthentication_VA_ReceiveAuthenticationResult_Ineligible
          by solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                          ~sk_voter.1, ~cid.1, ~token.1
                    ) ▶₀ #i2 )
        next
          case VoterAuthentication_VA_ReceiveAuthenticationResult_Unsuccessful
          by solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                          ~sk_voter.1, ~cid.1, ~token.1
                    ) ▶₀ #i2 )
        qed
      qed
    qed
  next
    case VoterAuthentication_VA_ReceiveAuthenticationResult_Ineligible
    solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V, ~sk_voter,
                                                 ~cid, ~token
           ) ▶₀ #i1 )
      case VoterAuthentication_VA_ReceiveAuthenticationComplete
      solve( SecureReceive( ~cid, <~ec, 'EAS'>, ~va_id,
                            <'EAS_Authentication_Result', 'ineligible', ~ec, pk(~sk_voter),
                             'ineligible'>
             ) ▶₁ #i1 )
        case SecureChannel_Receive_case_1
        solve( VA_ReceiveAuthenticationResult_Trace( ~ec, ~va_id, res2, pseudo2,
                                                     pk2, bs2
               ) @ #i2 )
          case VoterAuthentication_VA_ReceiveAuthenticationResult_Eligible
          by solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                          ~sk_voter.1, ~cid.1, ~token.1
                    ) ▶₀ #i2 )
        next
          case VoterAuthentication_VA_ReceiveAuthenticationResult_Ineligible
          by contradiction /* from formulas */
        next
          case VoterAuthentication_VA_ReceiveAuthenticationResult_Unsuccessful
          by solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                          ~sk_voter.1, ~cid.1, ~token.1
                    ) ▶₀ #i2 )
        qed
      next
        case SecureChannel_Receive_case_2
        solve( VA_ReceiveAuthenticationResult_Trace( ~ec, ~va_id, res2, pseudo2,
                                                     pk2, bs2
               ) @ #i2 )
          case VoterAuthentication_VA_ReceiveAuthenticationResult_Eligible
          by solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                          ~sk_voter.1, ~cid.1, ~token.1
                    ) ▶₀ #i2 )
        next
          case VoterAuthentication_VA_ReceiveAuthenticationResult_Ineligible
          by contradiction /* from formulas */
        next
          case VoterAuthentication_VA_ReceiveAuthenticationResult_Unsuccessful
          by solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                          ~sk_voter.1, ~cid.1, ~token.1
                    ) ▶₀ #i2 )
        qed
      next
        case SecureChannel_Receive_case_3
        solve( VA_ReceiveAuthenticationResult_Trace( ~ec, ~va_id, res2, pseudo2,
                                                     pk2, bs2
               ) @ #i2 )
          case VoterAuthentication_VA_ReceiveAuthenticationResult_Eligible
          by solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                          ~sk_voter.1, ~cid.1, ~token.1
                    ) ▶₀ #i2 )
        next
          case VoterAuthentication_VA_ReceiveAuthenticationResult_Ineligible
          by contradiction /* from formulas */
        next
          case VoterAuthentication_VA_ReceiveAuthenticationResult_Unsuccessful
          by solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                          ~sk_voter.1, ~cid.1, ~token.1
                    ) ▶₀ #i2 )
        qed
      next
        case SecureChannel_Receive_case_4
        solve( VA_ReceiveAuthenticationResult_Trace( ~ec, ~va_id, res2, pseudo2,
                                                     pk2, bs2
               ) @ #i2 )
          case VoterAuthentication_VA_ReceiveAuthenticationResult_Eligible
          by solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                          ~sk_voter.1, ~cid.1, ~token.1
                    ) ▶₀ #i2 )
        next
          case VoterAuthentication_VA_ReceiveAuthenticationResult_Ineligible
          by contradiction /* from formulas */
        next
          case VoterAuthentication_VA_ReceiveAuthenticationResult_Unsuccessful
          by solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                          ~sk_voter.1, ~cid.1, ~token.1
                    ) ▶₀ #i2 )
        qed
      next
        case SecureChannel_Receive_case_5
        solve( VA_ReceiveAuthenticationResult_Trace( ~ec, ~va_id, res2, pseudo2,
                                                     pk2, bs2
               ) @ #i2 )
          case VoterAuthentication_VA_ReceiveAuthenticationResult_Eligible
          by solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                          ~sk_voter.1, ~cid.1, ~token.1
                    ) ▶₀ #i2 )
        next
          case VoterAuthentication_VA_ReceiveAuthenticationResult_Ineligible
          by contradiction /* from formulas */
        next
          case VoterAuthentication_VA_ReceiveAuthenticationResult_Unsuccessful
          by solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                          ~sk_voter.1, ~cid.1, ~token.1
                    ) ▶₀ #i2 )
        qed
      qed
    qed
  next
    case VoterAuthentication_VA_ReceiveAuthenticationResult_Unsuccessful
    solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V, ~sk_voter,
                                                 ~cid, ~token
           ) ▶₀ #i1 )
      case VoterAuthentication_VA_ReceiveAuthenticationComplete
      solve( SecureReceive( ~cid, <~ec, 'EAS'>, ~va_id,
                            <'EAS_Authentication_Result', 'unsuccessful', ~ec, pk(~sk_voter),
                             'ineligible'>
             ) ▶₁ #i1 )
        case SecureChannel_Receive_case_1
        solve( VA_ReceiveAuthenticationResult_Trace( ~ec, ~va_id, res2, pseudo2,
                                                     pk2, bs2
               ) @ #i2 )
          case VoterAuthentication_VA_ReceiveAuthenticationResult_Eligible
          by solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                          ~sk_voter.1, ~cid.1, ~token.1
                    ) ▶₀ #i2 )
        next
          case VoterAuthentication_VA_ReceiveAuthenticationResult_Ineligible
          by solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                          ~sk_voter.1, ~cid.1, ~token.1
                    ) ▶₀ #i2 )
        next
          case VoterAuthentication_VA_ReceiveAuthenticationResult_Unsuccessful
          by contradiction /* from formulas */
        qed
      next
        case SecureChannel_Receive_case_2
        solve( VA_ReceiveAuthenticationResult_Trace( ~ec, ~va_id, res2, pseudo2,
                                                     pk2, bs2
               ) @ #i2 )
          case VoterAuthentication_VA_ReceiveAuthenticationResult_Eligible
          by solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                          ~sk_voter.1, ~cid.1, ~token.1
                    ) ▶₀ #i2 )
        next
          case VoterAuthentication_VA_ReceiveAuthenticationResult_Ineligible
          by solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                          ~sk_voter.1, ~cid.1, ~token.1
                    ) ▶₀ #i2 )
        next
          case VoterAuthentication_VA_ReceiveAuthenticationResult_Unsuccessful
          by contradiction /* from formulas */
        qed
      next
        case SecureChannel_Receive_case_3
        solve( VA_ReceiveAuthenticationResult_Trace( ~ec, ~va_id, res2, pseudo2,
                                                     pk2, bs2
               ) @ #i2 )
          case VoterAuthentication_VA_ReceiveAuthenticationResult_Eligible
          by solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                          ~sk_voter.1, ~cid.1, ~token.1
                    ) ▶₀ #i2 )
        next
          case VoterAuthentication_VA_ReceiveAuthenticationResult_Ineligible
          by solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                          ~sk_voter.1, ~cid.1, ~token.1
                    ) ▶₀ #i2 )
        next
          case VoterAuthentication_VA_ReceiveAuthenticationResult_Unsuccessful
          by contradiction /* from formulas */
        qed
      next
        case SecureChannel_Receive_case_4
        solve( VA_ReceiveAuthenticationResult_Trace( ~ec, ~va_id, res2, pseudo2,
                                                     pk2, bs2
               ) @ #i2 )
          case VoterAuthentication_VA_ReceiveAuthenticationResult_Eligible
          by solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                          ~sk_voter.1, ~cid.1, ~token.1
                    ) ▶₀ #i2 )
        next
          case VoterAuthentication_VA_ReceiveAuthenticationResult_Ineligible
          by solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                          ~sk_voter.1, ~cid.1, ~token.1
                    ) ▶₀ #i2 )
        next
          case VoterAuthentication_VA_ReceiveAuthenticationResult_Unsuccessful
          by contradiction /* from formulas */
        qed
      next
        case SecureChannel_Receive_case_5
        solve( VA_ReceiveAuthenticationResult_Trace( ~ec, ~va_id, res2, pseudo2,
                                                     pk2, bs2
               ) @ #i2 )
          case VoterAuthentication_VA_ReceiveAuthenticationResult_Eligible
          by solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                          ~sk_voter.1, ~cid.1, ~token.1
                    ) ▶₀ #i2 )
        next
          case VoterAuthentication_VA_ReceiveAuthenticationResult_Ineligible
          by solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                          ~sk_voter.1, ~cid.1, ~token.1
                    ) ▶₀ #i2 )
        next
          case VoterAuthentication_VA_ReceiveAuthenticationResult_Unsuccessful
          by contradiction /* from formulas */
        qed
      qed
    qed
  qed
next
  case case_2
  solve( VA_ReceiveAuthenticationResult_Trace( ec, va_id, res1, pseudo1,
                                               pk1, bs1
         ) @ #i1 )
    case VoterAuthentication_VA_ReceiveAuthenticationResult_Eligible
    solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V, ~sk_voter,
                                                 ~cid, ~token
           ) ▶₀ #i1 )
      case VoterAuthentication_VA_ReceiveAuthenticationComplete
      solve( SecureReceive( ~cid, <~ec, 'EAS'>, ~va_id,
                            <'EAS_Authentication_Result', 'eligible', ~ec, pk(~sk_voter),
                             <'VoterAuthorization', ~ec, pseudo1, pk(~sk_voter), bs1, ts>, sig_auth>
             ) ▶₁ #i1 )
        case SecureChannel_Receive_case_1
        solve( VA_ReceiveAuthenticationResult_Trace( ~ec, ~va_id, res2, pseudo2,
                                                     pk2, bs2
               ) @ #i2 )
          case VoterAuthentication_VA_ReceiveAuthenticationResult_Eligible
          solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                       ~sk_voter.1, ~cid.1, ~token.1
                 ) ▶₀ #i2 )
            case VoterAuthentication_VA_ReceiveAuthenticationComplete
            by contradiction /* from formulas */
          qed
        next
          case VoterAuthentication_VA_ReceiveAuthenticationResult_Ineligible
          by solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                          ~sk_voter.1, ~cid.1, ~token.1
                    ) ▶₀ #i2 )
        next
          case VoterAuthentication_VA_ReceiveAuthenticationResult_Unsuccessful
          by solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                          ~sk_voter.1, ~cid.1, ~token.1
                    ) ▶₀ #i2 )
        qed
      next
        case SecureChannel_Receive_case_2
        solve( VA_ReceiveAuthenticationResult_Trace( ~ec, ~va_id, res2, pseudo2,
                                                     pk2, bs2
               ) @ #i2 )
          case VoterAuthentication_VA_ReceiveAuthenticationResult_Eligible
          solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                       ~sk_voter.1, ~cid.1, ~token.1
                 ) ▶₀ #i2 )
            case VoterAuthentication_VA_ReceiveAuthenticationComplete
            by contradiction /* from formulas */
          qed
        next
          case VoterAuthentication_VA_ReceiveAuthenticationResult_Ineligible
          by solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                          ~sk_voter.1, ~cid.1, ~token.1
                    ) ▶₀ #i2 )
        next
          case VoterAuthentication_VA_ReceiveAuthenticationResult_Unsuccessful
          by solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                          ~sk_voter.1, ~cid.1, ~token.1
                    ) ▶₀ #i2 )
        qed
      next
        case SecureChannel_Receive_case_3
        solve( VA_ReceiveAuthenticationResult_Trace( ~ec, ~va_id, res2, pseudo2,
                                                     pk2, bs2
               ) @ #i2 )
          case VoterAuthentication_VA_ReceiveAuthenticationResult_Eligible
          solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                       ~sk_voter.1, ~cid.1, ~token.1
                 ) ▶₀ #i2 )
            case VoterAuthentication_VA_ReceiveAuthenticationComplete
            by contradiction /* from formulas */
          qed
        next
          case VoterAuthentication_VA_ReceiveAuthenticationResult_Ineligible
          by solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                          ~sk_voter.1, ~cid.1, ~token.1
                    ) ▶₀ #i2 )
        next
          case VoterAuthentication_VA_ReceiveAuthenticationResult_Unsuccessful
          by solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                          ~sk_voter.1, ~cid.1, ~token.1
                    ) ▶₀ #i2 )
        qed
      next
        case SecureChannel_Receive_case_4
        solve( VA_ReceiveAuthenticationResult_Trace( ~ec, ~va_id, res2, pseudo2,
                                                     pk2, bs2
               ) @ #i2 )
          case VoterAuthentication_VA_ReceiveAuthenticationResult_Eligible
          solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                       ~sk_voter.1, ~cid.1, ~token.1
                 ) ▶₀ #i2 )
            case VoterAuthentication_VA_ReceiveAuthenticationComplete
            by contradiction /* from formulas */
          qed
        next
          case VoterAuthentication_VA_ReceiveAuthenticationResult_Ineligible
          by solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                          ~sk_voter.1, ~cid.1, ~token.1
                    ) ▶₀ #i2 )
        next
          case VoterAuthentication_VA_ReceiveAuthenticationResult_Unsuccessful
          by solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                          ~sk_voter.1, ~cid.1, ~token.1
                    ) ▶₀ #i2 )
        qed
      next
        case SecureChannel_Receive_case_5
        solve( VA_ReceiveAuthenticationResult_Trace( ~ec, ~va_id, res2, pseudo2,
                                                     pk2, bs2
               ) @ #i2 )
          case VoterAuthentication_VA_ReceiveAuthenticationResult_Eligible
          solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                       ~sk_voter.1, ~cid.1, ~token.1
                 ) ▶₀ #i2 )
            case VoterAuthentication_VA_ReceiveAuthenticationComplete
            by contradiction /* from formulas */
          qed
        next
          case VoterAuthentication_VA_ReceiveAuthenticationResult_Ineligible
          by solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                          ~sk_voter.1, ~cid.1, ~token.1
                    ) ▶₀ #i2 )
        next
          case VoterAuthentication_VA_ReceiveAuthenticationResult_Unsuccessful
          by solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                          ~sk_voter.1, ~cid.1, ~token.1
                    ) ▶₀ #i2 )
        qed
      qed
    qed
  next
    case VoterAuthentication_VA_ReceiveAuthenticationResult_Ineligible
    solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V, ~sk_voter,
                                                 ~cid, ~token
           ) ▶₀ #i1 )
      case VoterAuthentication_VA_ReceiveAuthenticationComplete
      solve( SecureReceive( ~cid, <~ec, 'EAS'>, ~va_id,
                            <'EAS_Authentication_Result', 'ineligible', ~ec, pk(~sk_voter),
                             'ineligible'>
             ) ▶₁ #i1 )
        case SecureChannel_Receive_case_1
        solve( VA_ReceiveAuthenticationResult_Trace( ~ec, ~va_id, res2, pseudo2,
                                                     pk2, bs2
               ) @ #i2 )
          case VoterAuthentication_VA_ReceiveAuthenticationResult_Eligible
          by solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                          ~sk_voter.1, ~cid.1, ~token.1
                    ) ▶₀ #i2 )
        next
          case VoterAuthentication_VA_ReceiveAuthenticationResult_Ineligible
          by contradiction /* from formulas */
        next
          case VoterAuthentication_VA_ReceiveAuthenticationResult_Unsuccessful
          by contradiction /* from formulas */
        qed
      next
        case SecureChannel_Receive_case_2
        solve( VA_ReceiveAuthenticationResult_Trace( ~ec, ~va_id, res2, pseudo2,
                                                     pk2, bs2
               ) @ #i2 )
          case VoterAuthentication_VA_ReceiveAuthenticationResult_Eligible
          by solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                          ~sk_voter.1, ~cid.1, ~token.1
                    ) ▶₀ #i2 )
        next
          case VoterAuthentication_VA_ReceiveAuthenticationResult_Ineligible
          by contradiction /* from formulas */
        next
          case VoterAuthentication_VA_ReceiveAuthenticationResult_Unsuccessful
          by contradiction /* from formulas */
        qed
      next
        case SecureChannel_Receive_case_3
        solve( VA_ReceiveAuthenticationResult_Trace( ~ec, ~va_id, res2, pseudo2,
                                                     pk2, bs2
               ) @ #i2 )
          case VoterAuthentication_VA_ReceiveAuthenticationResult_Eligible
          by solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                          ~sk_voter.1, ~cid.1, ~token.1
                    ) ▶₀ #i2 )
        next
          case VoterAuthentication_VA_ReceiveAuthenticationResult_Ineligible
          by contradiction /* from formulas */
        next
          case VoterAuthentication_VA_ReceiveAuthenticationResult_Unsuccessful
          by contradiction /* from formulas */
        qed
      next
        case SecureChannel_Receive_case_4
        solve( VA_ReceiveAuthenticationResult_Trace( ~ec, ~va_id, res2, pseudo2,
                                                     pk2, bs2
               ) @ #i2 )
          case VoterAuthentication_VA_ReceiveAuthenticationResult_Eligible
          by solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                          ~sk_voter.1, ~cid.1, ~token.1
                    ) ▶₀ #i2 )
        next
          case VoterAuthentication_VA_ReceiveAuthenticationResult_Ineligible
          by contradiction /* from formulas */
        next
          case VoterAuthentication_VA_ReceiveAuthenticationResult_Unsuccessful
          by contradiction /* from formulas */
        qed
      next
        case SecureChannel_Receive_case_5
        solve( VA_ReceiveAuthenticationResult_Trace( ~ec, ~va_id, res2, pseudo2,
                                                     pk2, bs2
               ) @ #i2 )
          case VoterAuthentication_VA_ReceiveAuthenticationResult_Eligible
          by solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                          ~sk_voter.1, ~cid.1, ~token.1
                    ) ▶₀ #i2 )
        next
          case VoterAuthentication_VA_ReceiveAuthenticationResult_Ineligible
          by contradiction /* from formulas */
        next
          case VoterAuthentication_VA_ReceiveAuthenticationResult_Unsuccessful
          by contradiction /* from formulas */
        qed
      qed
    qed
  next
    case VoterAuthentication_VA_ReceiveAuthenticationResult_Unsuccessful
    solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V, ~sk_voter,
                                                 ~cid, ~token
           ) ▶₀ #i1 )
      case VoterAuthentication_VA_ReceiveAuthenticationComplete
      solve( SecureReceive( ~cid, <~ec, 'EAS'>, ~va_id,
                            <'EAS_Authentication_Result', 'unsuccessful', ~ec, pk(~sk_voter),
                             'ineligible'>
             ) ▶₁ #i1 )
        case SecureChannel_Receive_case_1
        solve( VA_ReceiveAuthenticationResult_Trace( ~ec, ~va_id, res2, pseudo2,
                                                     pk2, bs2
               ) @ #i2 )
          case VoterAuthentication_VA_ReceiveAuthenticationResult_Eligible
          by solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                          ~sk_voter.1, ~cid.1, ~token.1
                    ) ▶₀ #i2 )
        next
          case VoterAuthentication_VA_ReceiveAuthenticationResult_Ineligible
          by contradiction /* from formulas */
        next
          case VoterAuthentication_VA_ReceiveAuthenticationResult_Unsuccessful
          by contradiction /* from formulas */
        qed
      next
        case SecureChannel_Receive_case_2
        solve( VA_ReceiveAuthenticationResult_Trace( ~ec, ~va_id, res2, pseudo2,
                                                     pk2, bs2
               ) @ #i2 )
          case VoterAuthentication_VA_ReceiveAuthenticationResult_Eligible
          by solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                          ~sk_voter.1, ~cid.1, ~token.1
                    ) ▶₀ #i2 )
        next
          case VoterAuthentication_VA_ReceiveAuthenticationResult_Ineligible
          by contradiction /* from formulas */
        next
          case VoterAuthentication_VA_ReceiveAuthenticationResult_Unsuccessful
          by contradiction /* from formulas */
        qed
      next
        case SecureChannel_Receive_case_3
        solve( VA_ReceiveAuthenticationResult_Trace( ~ec, ~va_id, res2, pseudo2,
                                                     pk2, bs2
               ) @ #i2 )
          case VoterAuthentication_VA_ReceiveAuthenticationResult_Eligible
          by solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                          ~sk_voter.1, ~cid.1, ~token.1
                    ) ▶₀ #i2 )
        next
          case VoterAuthentication_VA_ReceiveAuthenticationResult_Ineligible
          by contradiction /* from formulas */
        next
          case VoterAuthentication_VA_ReceiveAuthenticationResult_Unsuccessful
          by contradiction /* from formulas */
        qed
      next
        case SecureChannel_Receive_case_4
        solve( VA_ReceiveAuthenticationResult_Trace( ~ec, ~va_id, res2, pseudo2,
                                                     pk2, bs2
               ) @ #i2 )
          case VoterAuthentication_VA_ReceiveAuthenticationResult_Eligible
          by solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                          ~sk_voter.1, ~cid.1, ~token.1
                    ) ▶₀ #i2 )
        next
          case VoterAuthentication_VA_ReceiveAuthenticationResult_Ineligible
          by contradiction /* from formulas */
        next
          case VoterAuthentication_VA_ReceiveAuthenticationResult_Unsuccessful
          by contradiction /* from formulas */
        qed
      next
        case SecureChannel_Receive_case_5
        solve( VA_ReceiveAuthenticationResult_Trace( ~ec, ~va_id, res2, pseudo2,
                                                     pk2, bs2
               ) @ #i2 )
          case VoterAuthentication_VA_ReceiveAuthenticationResult_Eligible
          by solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                          ~sk_voter.1, ~cid.1, ~token.1
                    ) ▶₀ #i2 )
        next
          case VoterAuthentication_VA_ReceiveAuthenticationResult_Ineligible
          by contradiction /* from formulas */
        next
          case VoterAuthentication_VA_ReceiveAuthenticationResult_Unsuccessful
          by contradiction /* from formulas */
        qed
      qed
    qed
  qed
next
  case case_3
  solve( VA_ReceiveAuthenticationResult_Trace( ec, va_id, res1, pseudo1,
                                               pk1, bs1
         ) @ #i1 )
    case VoterAuthentication_VA_ReceiveAuthenticationResult_Eligible
    solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V, ~sk_voter,
                                                 ~cid, ~token
           ) ▶₀ #i1 )
      case VoterAuthentication_VA_ReceiveAuthenticationComplete
      solve( SecureReceive( ~cid, <~ec, 'EAS'>, ~va_id,
                            <'EAS_Authentication_Result', 'eligible', ~ec, pk(~sk_voter),
                             <'VoterAuthorization', ~ec, pseudo1, pk(~sk_voter), bs1, ts>, sig_auth>
             ) ▶₁ #i1 )
        case SecureChannel_Receive_case_1
        solve( VA_ReceiveAuthenticationResult_Trace( ~ec, ~va_id, res2, pseudo2,
                                                     pk2, bs2
               ) @ #i2 )
          case VoterAuthentication_VA_ReceiveAuthenticationResult_Eligible
          solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                       ~sk_voter.1, ~cid.1, ~token.1
                 ) ▶₀ #i2 )
            case VoterAuthentication_VA_ReceiveAuthenticationComplete
            by contradiction /* from formulas */
          qed
        next
          case VoterAuthentication_VA_ReceiveAuthenticationResult_Ineligible
          by solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                          ~sk_voter.1, ~cid.1, ~token.1
                    ) ▶₀ #i2 )
        next
          case VoterAuthentication_VA_ReceiveAuthenticationResult_Unsuccessful
          by solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                          ~sk_voter.1, ~cid.1, ~token.1
                    ) ▶₀ #i2 )
        qed
      next
        case SecureChannel_Receive_case_2
        solve( VA_ReceiveAuthenticationResult_Trace( ~ec, ~va_id, res2, pseudo2,
                                                     pk2, bs2
               ) @ #i2 )
          case VoterAuthentication_VA_ReceiveAuthenticationResult_Eligible
          solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                       ~sk_voter.1, ~cid.1, ~token.1
                 ) ▶₀ #i2 )
            case VoterAuthentication_VA_ReceiveAuthenticationComplete
            by contradiction /* from formulas */
          qed
        next
          case VoterAuthentication_VA_ReceiveAuthenticationResult_Ineligible
          by solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                          ~sk_voter.1, ~cid.1, ~token.1
                    ) ▶₀ #i2 )
        next
          case VoterAuthentication_VA_ReceiveAuthenticationResult_Unsuccessful
          by solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                          ~sk_voter.1, ~cid.1, ~token.1
                    ) ▶₀ #i2 )
        qed
      next
        case SecureChannel_Receive_case_3
        solve( VA_ReceiveAuthenticationResult_Trace( ~ec, ~va_id, res2, pseudo2,
                                                     pk2, bs2
               ) @ #i2 )
          case VoterAuthentication_VA_ReceiveAuthenticationResult_Eligible
          solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                       ~sk_voter.1, ~cid.1, ~token.1
                 ) ▶₀ #i2 )
            case VoterAuthentication_VA_ReceiveAuthenticationComplete
            by contradiction /* from formulas */
          qed
        next
          case VoterAuthentication_VA_ReceiveAuthenticationResult_Ineligible
          by solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                          ~sk_voter.1, ~cid.1, ~token.1
                    ) ▶₀ #i2 )
        next
          case VoterAuthentication_VA_ReceiveAuthenticationResult_Unsuccessful
          by solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                          ~sk_voter.1, ~cid.1, ~token.1
                    ) ▶₀ #i2 )
        qed
      next
        case SecureChannel_Receive_case_4
        solve( VA_ReceiveAuthenticationResult_Trace( ~ec, ~va_id, res2, pseudo2,
                                                     pk2, bs2
               ) @ #i2 )
          case VoterAuthentication_VA_ReceiveAuthenticationResult_Eligible
          solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                       ~sk_voter.1, ~cid.1, ~token.1
                 ) ▶₀ #i2 )
            case VoterAuthentication_VA_ReceiveAuthenticationComplete
            by contradiction /* from formulas */
          qed
        next
          case VoterAuthentication_VA_ReceiveAuthenticationResult_Ineligible
          by solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                          ~sk_voter.1, ~cid.1, ~token.1
                    ) ▶₀ #i2 )
        next
          case VoterAuthentication_VA_ReceiveAuthenticationResult_Unsuccessful
          by solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                          ~sk_voter.1, ~cid.1, ~token.1
                    ) ▶₀ #i2 )
        qed
      next
        case SecureChannel_Receive_case_5
        solve( VA_ReceiveAuthenticationResult_Trace( ~ec, ~va_id, res2, pseudo2,
                                                     pk2, bs2
               ) @ #i2 )
          case VoterAuthentication_VA_ReceiveAuthenticationResult_Eligible
          solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                       ~sk_voter.1, ~cid.1, ~token.1
                 ) ▶₀ #i2 )
            case VoterAuthentication_VA_ReceiveAuthenticationComplete
            by contradiction /* from formulas */
          qed
        next
          case VoterAuthentication_VA_ReceiveAuthenticationResult_Ineligible
          by solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                          ~sk_voter.1, ~cid.1, ~token.1
                    ) ▶₀ #i2 )
        next
          case VoterAuthentication_VA_ReceiveAuthenticationResult_Unsuccessful
          by solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                          ~sk_voter.1, ~cid.1, ~token.1
                    ) ▶₀ #i2 )
        qed
      qed
    qed
  next
    case VoterAuthentication_VA_ReceiveAuthenticationResult_Ineligible
    solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V, ~sk_voter,
                                                 ~cid, ~token
           ) ▶₀ #i1 )
      case VoterAuthentication_VA_ReceiveAuthenticationComplete
      solve( SecureReceive( ~cid, <~ec, 'EAS'>, ~va_id,
                            <'EAS_Authentication_Result', 'ineligible', ~ec, pk(~sk_voter),
                             'ineligible'>
             ) ▶₁ #i1 )
        case SecureChannel_Receive_case_1
        solve( VA_ReceiveAuthenticationResult_Trace( ~ec, ~va_id, res2, pseudo2,
                                                     pk2, bs2
               ) @ #i2 )
          case VoterAuthentication_VA_ReceiveAuthenticationResult_Eligible
          by solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                          ~sk_voter.1, ~cid.1, ~token.1
                    ) ▶₀ #i2 )
        next
          case VoterAuthentication_VA_ReceiveAuthenticationResult_Ineligible
          solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                       ~sk_voter.1, ~cid.1, ~token.1
                 ) ▶₀ #i2 )
            case VoterAuthentication_VA_ReceiveAuthenticationComplete
            by contradiction /* from formulas */
          qed
        next
          case VoterAuthentication_VA_ReceiveAuthenticationResult_Unsuccessful
          by solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                          ~sk_voter.1, ~cid.1, ~token.1
                    ) ▶₀ #i2 )
        qed
      next
        case SecureChannel_Receive_case_2
        solve( VA_ReceiveAuthenticationResult_Trace( ~ec, ~va_id, res2, pseudo2,
                                                     pk2, bs2
               ) @ #i2 )
          case VoterAuthentication_VA_ReceiveAuthenticationResult_Eligible
          by solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                          ~sk_voter.1, ~cid.1, ~token.1
                    ) ▶₀ #i2 )
        next
          case VoterAuthentication_VA_ReceiveAuthenticationResult_Ineligible
          solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                       ~sk_voter.1, ~cid.1, ~token.1
                 ) ▶₀ #i2 )
            case VoterAuthentication_VA_ReceiveAuthenticationComplete
            by contradiction /* from formulas */
          qed
        next
          case VoterAuthentication_VA_ReceiveAuthenticationResult_Unsuccessful
          by solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                          ~sk_voter.1, ~cid.1, ~token.1
                    ) ▶₀ #i2 )
        qed
      next
        case SecureChannel_Receive_case_3
        solve( VA_ReceiveAuthenticationResult_Trace( ~ec, ~va_id, res2, pseudo2,
                                                     pk2, bs2
               ) @ #i2 )
          case VoterAuthentication_VA_ReceiveAuthenticationResult_Eligible
          by solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                          ~sk_voter.1, ~cid.1, ~token.1
                    ) ▶₀ #i2 )
        next
          case VoterAuthentication_VA_ReceiveAuthenticationResult_Ineligible
          solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                       ~sk_voter.1, ~cid.1, ~token.1
                 ) ▶₀ #i2 )
            case VoterAuthentication_VA_ReceiveAuthenticationComplete
            by contradiction /* from formulas */
          qed
        next
          case VoterAuthentication_VA_ReceiveAuthenticationResult_Unsuccessful
          by solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                          ~sk_voter.1, ~cid.1, ~token.1
                    ) ▶₀ #i2 )
        qed
      next
        case SecureChannel_Receive_case_4
        solve( VA_ReceiveAuthenticationResult_Trace( ~ec, ~va_id, res2, pseudo2,
                                                     pk2, bs2
               ) @ #i2 )
          case VoterAuthentication_VA_ReceiveAuthenticationResult_Eligible
          by solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                          ~sk_voter.1, ~cid.1, ~token.1
                    ) ▶₀ #i2 )
        next
          case VoterAuthentication_VA_ReceiveAuthenticationResult_Ineligible
          solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                       ~sk_voter.1, ~cid.1, ~token.1
                 ) ▶₀ #i2 )
            case VoterAuthentication_VA_ReceiveAuthenticationComplete
            by contradiction /* from formulas */
          qed
        next
          case VoterAuthentication_VA_ReceiveAuthenticationResult_Unsuccessful
          by solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                          ~sk_voter.1, ~cid.1, ~token.1
                    ) ▶₀ #i2 )
        qed
      next
        case SecureChannel_Receive_case_5
        solve( VA_ReceiveAuthenticationResult_Trace( ~ec, ~va_id, res2, pseudo2,
                                                     pk2, bs2
               ) @ #i2 )
          case VoterAuthentication_VA_ReceiveAuthenticationResult_Eligible
          by solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                          ~sk_voter.1, ~cid.1, ~token.1
                    ) ▶₀ #i2 )
        next
          case VoterAuthentication_VA_ReceiveAuthenticationResult_Ineligible
          solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                       ~sk_voter.1, ~cid.1, ~token.1
                 ) ▶₀ #i2 )
            case VoterAuthentication_VA_ReceiveAuthenticationComplete
            by contradiction /* from formulas */
          qed
        next
          case VoterAuthentication_VA_ReceiveAuthenticationResult_Unsuccessful
          by solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                          ~sk_voter.1, ~cid.1, ~token.1
                    ) ▶₀ #i2 )
        qed
      qed
    qed
  next
    case VoterAuthentication_VA_ReceiveAuthenticationResult_Unsuccessful
    solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V, ~sk_voter,
                                                 ~cid, ~token
           ) ▶₀ #i1 )
      case VoterAuthentication_VA_ReceiveAuthenticationComplete
      solve( SecureReceive( ~cid, <~ec, 'EAS'>, ~va_id,
                            <'EAS_Authentication_Result', 'unsuccessful', ~ec, pk(~sk_voter),
                             'ineligible'>
             ) ▶₁ #i1 )
        case SecureChannel_Receive_case_1
        solve( VA_ReceiveAuthenticationResult_Trace( ~ec, ~va_id, res2, pseudo2,
                                                     pk2, bs2
               ) @ #i2 )
          case VoterAuthentication_VA_ReceiveAuthenticationResult_Eligible
          by solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                          ~sk_voter.1, ~cid.1, ~token.1
                    ) ▶₀ #i2 )
        next
          case VoterAuthentication_VA_ReceiveAuthenticationResult_Ineligible
          by solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                          ~sk_voter.1, ~cid.1, ~token.1
                    ) ▶₀ #i2 )
        next
          case VoterAuthentication_VA_ReceiveAuthenticationResult_Unsuccessful
          solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                       ~sk_voter.1, ~cid.1, ~token.1
                 ) ▶₀ #i2 )
            case VoterAuthentication_VA_ReceiveAuthenticationComplete
            by contradiction /* from formulas */
          qed
        qed
      next
        case SecureChannel_Receive_case_2
        solve( VA_ReceiveAuthenticationResult_Trace( ~ec, ~va_id, res2, pseudo2,
                                                     pk2, bs2
               ) @ #i2 )
          case VoterAuthentication_VA_ReceiveAuthenticationResult_Eligible
          by solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                          ~sk_voter.1, ~cid.1, ~token.1
                    ) ▶₀ #i2 )
        next
          case VoterAuthentication_VA_ReceiveAuthenticationResult_Ineligible
          by solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                          ~sk_voter.1, ~cid.1, ~token.1
                    ) ▶₀ #i2 )
        next
          case VoterAuthentication_VA_ReceiveAuthenticationResult_Unsuccessful
          solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                       ~sk_voter.1, ~cid.1, ~token.1
                 ) ▶₀ #i2 )
            case VoterAuthentication_VA_ReceiveAuthenticationComplete
            by contradiction /* from formulas */
          qed
        qed
      next
        case SecureChannel_Receive_case_3
        solve( VA_ReceiveAuthenticationResult_Trace( ~ec, ~va_id, res2, pseudo2,
                                                     pk2, bs2
               ) @ #i2 )
          case VoterAuthentication_VA_ReceiveAuthenticationResult_Eligible
          by solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                          ~sk_voter.1, ~cid.1, ~token.1
                    ) ▶₀ #i2 )
        next
          case VoterAuthentication_VA_ReceiveAuthenticationResult_Ineligible
          by solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                          ~sk_voter.1, ~cid.1, ~token.1
                    ) ▶₀ #i2 )
        next
          case VoterAuthentication_VA_ReceiveAuthenticationResult_Unsuccessful
          solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                       ~sk_voter.1, ~cid.1, ~token.1
                 ) ▶₀ #i2 )
            case VoterAuthentication_VA_ReceiveAuthenticationComplete
            by contradiction /* from formulas */
          qed
        qed
      next
        case SecureChannel_Receive_case_4
        solve( VA_ReceiveAuthenticationResult_Trace( ~ec, ~va_id, res2, pseudo2,
                                                     pk2, bs2
               ) @ #i2 )
          case VoterAuthentication_VA_ReceiveAuthenticationResult_Eligible
          by solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                          ~sk_voter.1, ~cid.1, ~token.1
                    ) ▶₀ #i2 )
        next
          case VoterAuthentication_VA_ReceiveAuthenticationResult_Ineligible
          by solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                          ~sk_voter.1, ~cid.1, ~token.1
                    ) ▶₀ #i2 )
        next
          case VoterAuthentication_VA_ReceiveAuthenticationResult_Unsuccessful
          solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                       ~sk_voter.1, ~cid.1, ~token.1
                 ) ▶₀ #i2 )
            case VoterAuthentication_VA_ReceiveAuthenticationComplete
            by contradiction /* from formulas */
          qed
        qed
      next
        case SecureChannel_Receive_case_5
        solve( VA_ReceiveAuthenticationResult_Trace( ~ec, ~va_id, res2, pseudo2,
                                                     pk2, bs2
               ) @ #i2 )
          case VoterAuthentication_VA_ReceiveAuthenticationResult_Eligible
          by solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                          ~sk_voter.1, ~cid.1, ~token.1
                    ) ▶₀ #i2 )
        next
          case VoterAuthentication_VA_ReceiveAuthenticationResult_Ineligible
          by solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                          ~sk_voter.1, ~cid.1, ~token.1
                    ) ▶₀ #i2 )
        next
          case VoterAuthentication_VA_ReceiveAuthenticationResult_Unsuccessful
          solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                       ~sk_voter.1, ~cid.1, ~token.1
                 ) ▶₀ #i2 )
            case VoterAuthentication_VA_ReceiveAuthenticationComplete
            by contradiction /* from formulas */
          qed
        qed
      qed
    qed
  qed
next
  case case_4
  solve( VA_ReceiveAuthenticationResult_Trace( ec, va_id, res1, pseudo1,
                                               pk1, bs1
         ) @ #i1 )
    case VoterAuthentication_VA_ReceiveAuthenticationResult_Eligible
    solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V, ~sk_voter,
                                                 ~cid, ~token
           ) ▶₀ #i1 )
      case VoterAuthentication_VA_ReceiveAuthenticationComplete
      solve( SecureReceive( ~cid, <~ec, 'EAS'>, ~va_id,
                            <'EAS_Authentication_Result', 'eligible', ~ec, pk(~sk_voter),
                             <'VoterAuthorization', ~ec, pseudo1, pk(~sk_voter), bs1, ts>, sig_auth>
             ) ▶₁ #i1 )
        case SecureChannel_Receive_case_1
        solve( VA_ReceiveAuthenticationResult_Trace( ~ec, ~va_id, res2, pseudo2,
                                                     pk2, bs2
               ) @ #i2 )
          case VoterAuthentication_VA_ReceiveAuthenticationResult_Eligible
          solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                       ~sk_voter.1, ~cid.1, ~token.1
                 ) ▶₀ #i2 )
            case VoterAuthentication_VA_ReceiveAuthenticationComplete
            by contradiction /* from formulas */
          qed
        next
          case VoterAuthentication_VA_ReceiveAuthenticationResult_Ineligible
          by solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                          ~sk_voter.1, ~cid.1, ~token.1
                    ) ▶₀ #i2 )
        next
          case VoterAuthentication_VA_ReceiveAuthenticationResult_Unsuccessful
          by solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                          ~sk_voter.1, ~cid.1, ~token.1
                    ) ▶₀ #i2 )
        qed
      next
        case SecureChannel_Receive_case_2
        solve( VA_ReceiveAuthenticationResult_Trace( ~ec, ~va_id, res2, pseudo2,
                                                     pk2, bs2
               ) @ #i2 )
          case VoterAuthentication_VA_ReceiveAuthenticationResult_Eligible
          solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                       ~sk_voter.1, ~cid.1, ~token.1
                 ) ▶₀ #i2 )
            case VoterAuthentication_VA_ReceiveAuthenticationComplete
            by contradiction /* from formulas */
          qed
        next
          case VoterAuthentication_VA_ReceiveAuthenticationResult_Ineligible
          by solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                          ~sk_voter.1, ~cid.1, ~token.1
                    ) ▶₀ #i2 )
        next
          case VoterAuthentication_VA_ReceiveAuthenticationResult_Unsuccessful
          by solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                          ~sk_voter.1, ~cid.1, ~token.1
                    ) ▶₀ #i2 )
        qed
      next
        case SecureChannel_Receive_case_3
        solve( VA_ReceiveAuthenticationResult_Trace( ~ec, ~va_id, res2, pseudo2,
                                                     pk2, bs2
               ) @ #i2 )
          case VoterAuthentication_VA_ReceiveAuthenticationResult_Eligible
          solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                       ~sk_voter.1, ~cid.1, ~token.1
                 ) ▶₀ #i2 )
            case VoterAuthentication_VA_ReceiveAuthenticationComplete
            by contradiction /* from formulas */
          qed
        next
          case VoterAuthentication_VA_ReceiveAuthenticationResult_Ineligible
          by solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                          ~sk_voter.1, ~cid.1, ~token.1
                    ) ▶₀ #i2 )
        next
          case VoterAuthentication_VA_ReceiveAuthenticationResult_Unsuccessful
          by solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                          ~sk_voter.1, ~cid.1, ~token.1
                    ) ▶₀ #i2 )
        qed
      next
        case SecureChannel_Receive_case_4
        solve( VA_ReceiveAuthenticationResult_Trace( ~ec, ~va_id, res2, pseudo2,
                                                     pk2, bs2
               ) @ #i2 )
          case VoterAuthentication_VA_ReceiveAuthenticationResult_Eligible
          solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                       ~sk_voter.1, ~cid.1, ~token.1
                 ) ▶₀ #i2 )
            case VoterAuthentication_VA_ReceiveAuthenticationComplete
            by contradiction /* from formulas */
          qed
        next
          case VoterAuthentication_VA_ReceiveAuthenticationResult_Ineligible
          by solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                          ~sk_voter.1, ~cid.1, ~token.1
                    ) ▶₀ #i2 )
        next
          case VoterAuthentication_VA_ReceiveAuthenticationResult_Unsuccessful
          by solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                          ~sk_voter.1, ~cid.1, ~token.1
                    ) ▶₀ #i2 )
        qed
      next
        case SecureChannel_Receive_case_5
        solve( VA_ReceiveAuthenticationResult_Trace( ~ec, ~va_id, res2, pseudo2,
                                                     pk2, bs2
               ) @ #i2 )
          case VoterAuthentication_VA_ReceiveAuthenticationResult_Eligible
          solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                       ~sk_voter.1, ~cid.1, ~token.1
                 ) ▶₀ #i2 )
            case VoterAuthentication_VA_ReceiveAuthenticationComplete
            by contradiction /* from formulas */
          qed
        next
          case VoterAuthentication_VA_ReceiveAuthenticationResult_Ineligible
          by solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                          ~sk_voter.1, ~cid.1, ~token.1
                    ) ▶₀ #i2 )
        next
          case VoterAuthentication_VA_ReceiveAuthenticationResult_Unsuccessful
          by solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                          ~sk_voter.1, ~cid.1, ~token.1
                    ) ▶₀ #i2 )
        qed
      qed
    qed
  next
    case VoterAuthentication_VA_ReceiveAuthenticationResult_Ineligible
    solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V, ~sk_voter,
                                                 ~cid, ~token
           ) ▶₀ #i1 )
      case VoterAuthentication_VA_ReceiveAuthenticationComplete
      solve( SecureReceive( ~cid, <~ec, 'EAS'>, ~va_id,
                            <'EAS_Authentication_Result', 'ineligible', ~ec, pk(~sk_voter),
                             'ineligible'>
             ) ▶₁ #i1 )
        case SecureChannel_Receive_case_1
        solve( VA_ReceiveAuthenticationResult_Trace( ~ec, ~va_id, res2, pseudo2,
                                                     pk2, bs2
               ) @ #i2 )
          case VoterAuthentication_VA_ReceiveAuthenticationResult_Eligible
          by solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                          ~sk_voter.1, ~cid.1, ~token.1
                    ) ▶₀ #i2 )
        next
          case VoterAuthentication_VA_ReceiveAuthenticationResult_Ineligible
          by contradiction /* from formulas */
        next
          case VoterAuthentication_VA_ReceiveAuthenticationResult_Unsuccessful
          by contradiction /* from formulas */
        qed
      next
        case SecureChannel_Receive_case_2
        solve( VA_ReceiveAuthenticationResult_Trace( ~ec, ~va_id, res2, pseudo2,
                                                     pk2, bs2
               ) @ #i2 )
          case VoterAuthentication_VA_ReceiveAuthenticationResult_Eligible
          by solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                          ~sk_voter.1, ~cid.1, ~token.1
                    ) ▶₀ #i2 )
        next
          case VoterAuthentication_VA_ReceiveAuthenticationResult_Ineligible
          by contradiction /* from formulas */
        next
          case VoterAuthentication_VA_ReceiveAuthenticationResult_Unsuccessful
          by contradiction /* from formulas */
        qed
      next
        case SecureChannel_Receive_case_3
        solve( VA_ReceiveAuthenticationResult_Trace( ~ec, ~va_id, res2, pseudo2,
                                                     pk2, bs2
               ) @ #i2 )
          case VoterAuthentication_VA_ReceiveAuthenticationResult_Eligible
          by solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                          ~sk_voter.1, ~cid.1, ~token.1
                    ) ▶₀ #i2 )
        next
          case VoterAuthentication_VA_ReceiveAuthenticationResult_Ineligible
          by contradiction /* from formulas */
        next
          case VoterAuthentication_VA_ReceiveAuthenticationResult_Unsuccessful
          by contradiction /* from formulas */
        qed
      next
        case SecureChannel_Receive_case_4
        solve( VA_ReceiveAuthenticationResult_Trace( ~ec, ~va_id, res2, pseudo2,
                                                     pk2, bs2
               ) @ #i2 )
          case VoterAuthentication_VA_ReceiveAuthenticationResult_Eligible
          by solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                          ~sk_voter.1, ~cid.1, ~token.1
                    ) ▶₀ #i2 )
        next
          case VoterAuthentication_VA_ReceiveAuthenticationResult_Ineligible
          by contradiction /* from formulas */
        next
          case VoterAuthentication_VA_ReceiveAuthenticationResult_Unsuccessful
          by contradiction /* from formulas */
        qed
      next
        case SecureChannel_Receive_case_5
        solve( VA_ReceiveAuthenticationResult_Trace( ~ec, ~va_id, res2, pseudo2,
                                                     pk2, bs2
               ) @ #i2 )
          case VoterAuthentication_VA_ReceiveAuthenticationResult_Eligible
          by solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                          ~sk_voter.1, ~cid.1, ~token.1
                    ) ▶₀ #i2 )
        next
          case VoterAuthentication_VA_ReceiveAuthenticationResult_Ineligible
          by contradiction /* from formulas */
        next
          case VoterAuthentication_VA_ReceiveAuthenticationResult_Unsuccessful
          by contradiction /* from formulas */
        qed
      qed
    qed
  next
    case VoterAuthentication_VA_ReceiveAuthenticationResult_Unsuccessful
    solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V, ~sk_voter,
                                                 ~cid, ~token
           ) ▶₀ #i1 )
      case VoterAuthentication_VA_ReceiveAuthenticationComplete
      solve( SecureReceive( ~cid, <~ec, 'EAS'>, ~va_id,
                            <'EAS_Authentication_Result', 'unsuccessful', ~ec, pk(~sk_voter),
                             'ineligible'>
             ) ▶₁ #i1 )
        case SecureChannel_Receive_case_1
        solve( VA_ReceiveAuthenticationResult_Trace( ~ec, ~va_id, res2, pseudo2,
                                                     pk2, bs2
               ) @ #i2 )
          case VoterAuthentication_VA_ReceiveAuthenticationResult_Eligible
          by solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                          ~sk_voter.1, ~cid.1, ~token.1
                    ) ▶₀ #i2 )
        next
          case VoterAuthentication_VA_ReceiveAuthenticationResult_Ineligible
          by contradiction /* from formulas */
        next
          case VoterAuthentication_VA_ReceiveAuthenticationResult_Unsuccessful
          by contradiction /* from formulas */
        qed
      next
        case SecureChannel_Receive_case_2
        solve( VA_ReceiveAuthenticationResult_Trace( ~ec, ~va_id, res2, pseudo2,
                                                     pk2, bs2
               ) @ #i2 )
          case VoterAuthentication_VA_ReceiveAuthenticationResult_Eligible
          by solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                          ~sk_voter.1, ~cid.1, ~token.1
                    ) ▶₀ #i2 )
        next
          case VoterAuthentication_VA_ReceiveAuthenticationResult_Ineligible
          by contradiction /* from formulas */
        next
          case VoterAuthentication_VA_ReceiveAuthenticationResult_Unsuccessful
          by contradiction /* from formulas */
        qed
      next
        case SecureChannel_Receive_case_3
        solve( VA_ReceiveAuthenticationResult_Trace( ~ec, ~va_id, res2, pseudo2,
                                                     pk2, bs2
               ) @ #i2 )
          case VoterAuthentication_VA_ReceiveAuthenticationResult_Eligible
          by solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                          ~sk_voter.1, ~cid.1, ~token.1
                    ) ▶₀ #i2 )
        next
          case VoterAuthentication_VA_ReceiveAuthenticationResult_Ineligible
          by contradiction /* from formulas */
        next
          case VoterAuthentication_VA_ReceiveAuthenticationResult_Unsuccessful
          by contradiction /* from formulas */
        qed
      next
        case SecureChannel_Receive_case_4
        solve( VA_ReceiveAuthenticationResult_Trace( ~ec, ~va_id, res2, pseudo2,
                                                     pk2, bs2
               ) @ #i2 )
          case VoterAuthentication_VA_ReceiveAuthenticationResult_Eligible
          by solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                          ~sk_voter.1, ~cid.1, ~token.1
                    ) ▶₀ #i2 )
        next
          case VoterAuthentication_VA_ReceiveAuthenticationResult_Ineligible
          by contradiction /* from formulas */
        next
          case VoterAuthentication_VA_ReceiveAuthenticationResult_Unsuccessful
          by contradiction /* from formulas */
        qed
      next
        case SecureChannel_Receive_case_5
        solve( VA_ReceiveAuthenticationResult_Trace( ~ec, ~va_id, res2, pseudo2,
                                                     pk2, bs2
               ) @ #i2 )
          case VoterAuthentication_VA_ReceiveAuthenticationResult_Eligible
          by solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                          ~sk_voter.1, ~cid.1, ~token.1
                    ) ▶₀ #i2 )
        next
          case VoterAuthentication_VA_ReceiveAuthenticationResult_Ineligible
          by contradiction /* from formulas */
        next
          case VoterAuthentication_VA_ReceiveAuthenticationResult_Unsuccessful
          by contradiction /* from formulas */
        qed
      qed
    qed
  qed
next
  case case_5
  solve( (#i1 < #i2)  ∥ (#i2 < #i1) )
    case case_1
    solve( VA_ReceiveAuthenticationResult_Trace( ec, va_id, res1, pseudo1,
                                                 pk1, bs1
           ) @ #i1 )
      case VoterAuthentication_VA_ReceiveAuthenticationResult_Eligible
      solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V, ~sk_voter,
                                                   ~cid, ~token
             ) ▶₀ #i1 )
        case VoterAuthentication_VA_ReceiveAuthenticationComplete
        solve( SecureReceive( ~cid, <~ec, 'EAS'>, ~va_id,
                              <'EAS_Authentication_Result', 'eligible', ~ec, pk(~sk_voter),
                               <'VoterAuthorization', ~ec, pseudo1, pk(~sk_voter), bs1, ts>, sig_auth>
               ) ▶₁ #i1 )
          case SecureChannel_Receive_case_1
          solve( VA_ReceiveAuthenticationResult_Trace( ~ec, ~va_id, res2, pseudo2,
                                                       pk2, bs2
                 ) @ #i2 )
            case VoterAuthentication_VA_ReceiveAuthenticationResult_Eligible
            solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                         ~sk_voter.1, ~cid.1, ~token.1
                   ) ▶₀ #i2 )
              case VoterAuthentication_VA_ReceiveAuthenticationComplete
              by contradiction /* cyclic */
            qed
          next
            case VoterAuthentication_VA_ReceiveAuthenticationResult_Ineligible
            by solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                            ~sk_voter.1, ~cid.1, ~token.1
                      ) ▶₀ #i2 )
          next
            case VoterAuthentication_VA_ReceiveAuthenticationResult_Unsuccessful
            by solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                            ~sk_voter.1, ~cid.1, ~token.1
                      ) ▶₀ #i2 )
          qed
        next
          case SecureChannel_Receive_case_2
          solve( VA_ReceiveAuthenticationResult_Trace( ~ec, ~va_id, res2, pseudo2,
                                                       pk2, bs2
                 ) @ #i2 )
            case VoterAuthentication_VA_ReceiveAuthenticationResult_Eligible
            solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                         ~sk_voter.1, ~cid.1, ~token.1
                   ) ▶₀ #i2 )
              case VoterAuthentication_VA_ReceiveAuthenticationComplete
              by contradiction /* cyclic */
            qed
          next
            case VoterAuthentication_VA_ReceiveAuthenticationResult_Ineligible
            by solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                            ~sk_voter.1, ~cid.1, ~token.1
                      ) ▶₀ #i2 )
          next
            case VoterAuthentication_VA_ReceiveAuthenticationResult_Unsuccessful
            by solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                            ~sk_voter.1, ~cid.1, ~token.1
                      ) ▶₀ #i2 )
          qed
        next
          case SecureChannel_Receive_case_3
          solve( VA_ReceiveAuthenticationResult_Trace( ~ec, ~va_id, res2, pseudo2,
                                                       pk2, bs2
                 ) @ #i2 )
            case VoterAuthentication_VA_ReceiveAuthenticationResult_Eligible
            solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                         ~sk_voter.1, ~cid.1, ~token.1
                   ) ▶₀ #i2 )
              case VoterAuthentication_VA_ReceiveAuthenticationComplete
              by contradiction /* cyclic */
            qed
          next
            case VoterAuthentication_VA_ReceiveAuthenticationResult_Ineligible
            by solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                            ~sk_voter.1, ~cid.1, ~token.1
                      ) ▶₀ #i2 )
          next
            case VoterAuthentication_VA_ReceiveAuthenticationResult_Unsuccessful
            by solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                            ~sk_voter.1, ~cid.1, ~token.1
                      ) ▶₀ #i2 )
          qed
        next
          case SecureChannel_Receive_case_4
          solve( VA_ReceiveAuthenticationResult_Trace( ~ec, ~va_id, res2, pseudo2,
                                                       pk2, bs2
                 ) @ #i2 )
            case VoterAuthentication_VA_ReceiveAuthenticationResult_Eligible
            solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                         ~sk_voter.1, ~cid.1, ~token.1
                   ) ▶₀ #i2 )
              case VoterAuthentication_VA_ReceiveAuthenticationComplete
              by contradiction /* cyclic */
            qed
          next
            case VoterAuthentication_VA_ReceiveAuthenticationResult_Ineligible
            by solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                            ~sk_voter.1, ~cid.1, ~token.1
                      ) ▶₀ #i2 )
          next
            case VoterAuthentication_VA_ReceiveAuthenticationResult_Unsuccessful
            by solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                            ~sk_voter.1, ~cid.1, ~token.1
                      ) ▶₀ #i2 )
          qed
        next
          case SecureChannel_Receive_case_5
          solve( VA_ReceiveAuthenticationResult_Trace( ~ec, ~va_id, res2, pseudo2,
                                                       pk2, bs2
                 ) @ #i2 )
            case VoterAuthentication_VA_ReceiveAuthenticationResult_Eligible
            solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                         ~sk_voter.1, ~cid.1, ~token.1
                   ) ▶₀ #i2 )
              case VoterAuthentication_VA_ReceiveAuthenticationComplete
              by contradiction /* cyclic */
            qed
          next
            case VoterAuthentication_VA_ReceiveAuthenticationResult_Ineligible
            by solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                            ~sk_voter.1, ~cid.1, ~token.1
                      ) ▶₀ #i2 )
          next
            case VoterAuthentication_VA_ReceiveAuthenticationResult_Unsuccessful
            by solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                            ~sk_voter.1, ~cid.1, ~token.1
                      ) ▶₀ #i2 )
          qed
        qed
      qed
    next
      case VoterAuthentication_VA_ReceiveAuthenticationResult_Ineligible
      solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V, ~sk_voter,
                                                   ~cid, ~token
             ) ▶₀ #i1 )
        case VoterAuthentication_VA_ReceiveAuthenticationComplete
        solve( SecureReceive( ~cid, <~ec, 'EAS'>, ~va_id,
                              <'EAS_Authentication_Result', 'ineligible', ~ec, pk(~sk_voter),
                               'ineligible'>
               ) ▶₁ #i1 )
          case SecureChannel_Receive_case_1
          solve( VA_ReceiveAuthenticationResult_Trace( ~ec, ~va_id, res2, pseudo2,
                                                       pk2, bs2
                 ) @ #i2 )
            case VoterAuthentication_VA_ReceiveAuthenticationResult_Eligible
            by solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                            ~sk_voter.1, ~cid.1, ~token.1
                      ) ▶₀ #i2 )
          next
            case VoterAuthentication_VA_ReceiveAuthenticationResult_Ineligible
            solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                         ~sk_voter.1, ~cid.1, ~token.1
                   ) ▶₀ #i2 )
              case VoterAuthentication_VA_ReceiveAuthenticationComplete
              by contradiction /* cyclic */
            qed
          next
            case VoterAuthentication_VA_ReceiveAuthenticationResult_Unsuccessful
            by solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                            ~sk_voter.1, ~cid.1, ~token.1
                      ) ▶₀ #i2 )
          qed
        next
          case SecureChannel_Receive_case_2
          solve( VA_ReceiveAuthenticationResult_Trace( ~ec, ~va_id, res2, pseudo2,
                                                       pk2, bs2
                 ) @ #i2 )
            case VoterAuthentication_VA_ReceiveAuthenticationResult_Eligible
            by solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                            ~sk_voter.1, ~cid.1, ~token.1
                      ) ▶₀ #i2 )
          next
            case VoterAuthentication_VA_ReceiveAuthenticationResult_Ineligible
            solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                         ~sk_voter.1, ~cid.1, ~token.1
                   ) ▶₀ #i2 )
              case VoterAuthentication_VA_ReceiveAuthenticationComplete
              by contradiction /* cyclic */
            qed
          next
            case VoterAuthentication_VA_ReceiveAuthenticationResult_Unsuccessful
            by solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                            ~sk_voter.1, ~cid.1, ~token.1
                      ) ▶₀ #i2 )
          qed
        next
          case SecureChannel_Receive_case_3
          solve( VA_ReceiveAuthenticationResult_Trace( ~ec, ~va_id, res2, pseudo2,
                                                       pk2, bs2
                 ) @ #i2 )
            case VoterAuthentication_VA_ReceiveAuthenticationResult_Eligible
            by solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                            ~sk_voter.1, ~cid.1, ~token.1
                      ) ▶₀ #i2 )
          next
            case VoterAuthentication_VA_ReceiveAuthenticationResult_Ineligible
            solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                         ~sk_voter.1, ~cid.1, ~token.1
                   ) ▶₀ #i2 )
              case VoterAuthentication_VA_ReceiveAuthenticationComplete
              by contradiction /* cyclic */
            qed
          next
            case VoterAuthentication_VA_ReceiveAuthenticationResult_Unsuccessful
            by solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                            ~sk_voter.1, ~cid.1, ~token.1
                      ) ▶₀ #i2 )
          qed
        next
          case SecureChannel_Receive_case_4
          solve( VA_ReceiveAuthenticationResult_Trace( ~ec, ~va_id, res2, pseudo2,
                                                       pk2, bs2
                 ) @ #i2 )
            case VoterAuthentication_VA_ReceiveAuthenticationResult_Eligible
            by solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                            ~sk_voter.1, ~cid.1, ~token.1
                      ) ▶₀ #i2 )
          next
            case VoterAuthentication_VA_ReceiveAuthenticationResult_Ineligible
            solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                         ~sk_voter.1, ~cid.1, ~token.1
                   ) ▶₀ #i2 )
              case VoterAuthentication_VA_ReceiveAuthenticationComplete
              by contradiction /* cyclic */
            qed
          next
            case VoterAuthentication_VA_ReceiveAuthenticationResult_Unsuccessful
            by solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                            ~sk_voter.1, ~cid.1, ~token.1
                      ) ▶₀ #i2 )
          qed
        next
          case SecureChannel_Receive_case_5
          solve( VA_ReceiveAuthenticationResult_Trace( ~ec, ~va_id, res2, pseudo2,
                                                       pk2, bs2
                 ) @ #i2 )
            case VoterAuthentication_VA_ReceiveAuthenticationResult_Eligible
            by solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                            ~sk_voter.1, ~cid.1, ~token.1
                      ) ▶₀ #i2 )
          next
            case VoterAuthentication_VA_ReceiveAuthenticationResult_Ineligible
            solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                         ~sk_voter.1, ~cid.1, ~token.1
                   ) ▶₀ #i2 )
              case VoterAuthentication_VA_ReceiveAuthenticationComplete
              by contradiction /* cyclic */
            qed
          next
            case VoterAuthentication_VA_ReceiveAuthenticationResult_Unsuccessful
            by solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                            ~sk_voter.1, ~cid.1, ~token.1
                      ) ▶₀ #i2 )
          qed
        qed
      qed
    next
      case VoterAuthentication_VA_ReceiveAuthenticationResult_Unsuccessful
      solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V, ~sk_voter,
                                                   ~cid, ~token
             ) ▶₀ #i1 )
        case VoterAuthentication_VA_ReceiveAuthenticationComplete
        solve( SecureReceive( ~cid, <~ec, 'EAS'>, ~va_id,
                              <'EAS_Authentication_Result', 'unsuccessful', ~ec, pk(~sk_voter),
                               'ineligible'>
               ) ▶₁ #i1 )
          case SecureChannel_Receive_case_1
          solve( VA_ReceiveAuthenticationResult_Trace( ~ec, ~va_id, res2, pseudo2,
                                                       pk2, bs2
                 ) @ #i2 )
            case VoterAuthentication_VA_ReceiveAuthenticationResult_Eligible
            by solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                            ~sk_voter.1, ~cid.1, ~token.1
                      ) ▶₀ #i2 )
          next
            case VoterAuthentication_VA_ReceiveAuthenticationResult_Ineligible
            by solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                            ~sk_voter.1, ~cid.1, ~token.1
                      ) ▶₀ #i2 )
          next
            case VoterAuthentication_VA_ReceiveAuthenticationResult_Unsuccessful
            solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                         ~sk_voter.1, ~cid.1, ~token.1
                   ) ▶₀ #i2 )
              case VoterAuthentication_VA_ReceiveAuthenticationComplete
              by contradiction /* cyclic */
            qed
          qed
        next
          case SecureChannel_Receive_case_2
          solve( VA_ReceiveAuthenticationResult_Trace( ~ec, ~va_id, res2, pseudo2,
                                                       pk2, bs2
                 ) @ #i2 )
            case VoterAuthentication_VA_ReceiveAuthenticationResult_Eligible
            by solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                            ~sk_voter.1, ~cid.1, ~token.1
                      ) ▶₀ #i2 )
          next
            case VoterAuthentication_VA_ReceiveAuthenticationResult_Ineligible
            by solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                            ~sk_voter.1, ~cid.1, ~token.1
                      ) ▶₀ #i2 )
          next
            case VoterAuthentication_VA_ReceiveAuthenticationResult_Unsuccessful
            solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                         ~sk_voter.1, ~cid.1, ~token.1
                   ) ▶₀ #i2 )
              case VoterAuthentication_VA_ReceiveAuthenticationComplete
              by contradiction /* cyclic */
            qed
          qed
        next
          case SecureChannel_Receive_case_3
          solve( VA_ReceiveAuthenticationResult_Trace( ~ec, ~va_id, res2, pseudo2,
                                                       pk2, bs2
                 ) @ #i2 )
            case VoterAuthentication_VA_ReceiveAuthenticationResult_Eligible
            by solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                            ~sk_voter.1, ~cid.1, ~token.1
                      ) ▶₀ #i2 )
          next
            case VoterAuthentication_VA_ReceiveAuthenticationResult_Ineligible
            by solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                            ~sk_voter.1, ~cid.1, ~token.1
                      ) ▶₀ #i2 )
          next
            case VoterAuthentication_VA_ReceiveAuthenticationResult_Unsuccessful
            solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                         ~sk_voter.1, ~cid.1, ~token.1
                   ) ▶₀ #i2 )
              case VoterAuthentication_VA_ReceiveAuthenticationComplete
              by contradiction /* cyclic */
            qed
          qed
        next
          case SecureChannel_Receive_case_4
          solve( VA_ReceiveAuthenticationResult_Trace( ~ec, ~va_id, res2, pseudo2,
                                                       pk2, bs2
                 ) @ #i2 )
            case VoterAuthentication_VA_ReceiveAuthenticationResult_Eligible
            by solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                            ~sk_voter.1, ~cid.1, ~token.1
                      ) ▶₀ #i2 )
          next
            case VoterAuthentication_VA_ReceiveAuthenticationResult_Ineligible
            by solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                            ~sk_voter.1, ~cid.1, ~token.1
                      ) ▶₀ #i2 )
          next
            case VoterAuthentication_VA_ReceiveAuthenticationResult_Unsuccessful
            solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                         ~sk_voter.1, ~cid.1, ~token.1
                   ) ▶₀ #i2 )
              case VoterAuthentication_VA_ReceiveAuthenticationComplete
              by contradiction /* cyclic */
            qed
          qed
        next
          case SecureChannel_Receive_case_5
          solve( VA_ReceiveAuthenticationResult_Trace( ~ec, ~va_id, res2, pseudo2,
                                                       pk2, bs2
                 ) @ #i2 )
            case VoterAuthentication_VA_ReceiveAuthenticationResult_Eligible
            by solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                            ~sk_voter.1, ~cid.1, ~token.1
                      ) ▶₀ #i2 )
          next
            case VoterAuthentication_VA_ReceiveAuthenticationResult_Ineligible
            by solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                            ~sk_voter.1, ~cid.1, ~token.1
                      ) ▶₀ #i2 )
          next
            case VoterAuthentication_VA_ReceiveAuthenticationResult_Unsuccessful
            solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                         ~sk_voter.1, ~cid.1, ~token.1
                   ) ▶₀ #i2 )
              case VoterAuthentication_VA_ReceiveAuthenticationComplete
              by contradiction /* cyclic */
            qed
          qed
        qed
      qed
    qed
  next
    case case_2
    solve( VA_ReceiveAuthenticationResult_Trace( ec, va_id, res1, pseudo1,
                                                 pk1, bs1
           ) @ #i1 )
      case VoterAuthentication_VA_ReceiveAuthenticationResult_Eligible
      solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V, ~sk_voter,
                                                   ~cid, ~token
             ) ▶₀ #i1 )
        case VoterAuthentication_VA_ReceiveAuthenticationComplete
        solve( SecureReceive( ~cid, <~ec, 'EAS'>, ~va_id,
                              <'EAS_Authentication_Result', 'eligible', ~ec, pk(~sk_voter),
                               <'VoterAuthorization', ~ec, pseudo1, pk(~sk_voter), bs1, ts>, sig_auth>
               ) ▶₁ #i1 )
          case SecureChannel_Receive_case_1
          solve( VA_ReceiveAuthenticationResult_Trace( ~ec, ~va_id, res2, pseudo2,
                                                       pk2, bs2
                 ) @ #i2 )
            case VoterAuthentication_VA_ReceiveAuthenticationResult_Eligible
            solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                         ~sk_voter.1, ~cid.1, ~token.1
                   ) ▶₀ #i2 )
              case VoterAuthentication_VA_ReceiveAuthenticationComplete
              by contradiction /* cyclic */
            qed
          next
            case VoterAuthentication_VA_ReceiveAuthenticationResult_Ineligible
            by solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                            ~sk_voter.1, ~cid.1, ~token.1
                      ) ▶₀ #i2 )
          next
            case VoterAuthentication_VA_ReceiveAuthenticationResult_Unsuccessful
            by solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                            ~sk_voter.1, ~cid.1, ~token.1
                      ) ▶₀ #i2 )
          qed
        next
          case SecureChannel_Receive_case_2
          solve( VA_ReceiveAuthenticationResult_Trace( ~ec, ~va_id, res2, pseudo2,
                                                       pk2, bs2
                 ) @ #i2 )
            case VoterAuthentication_VA_ReceiveAuthenticationResult_Eligible
            solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                         ~sk_voter.1, ~cid.1, ~token.1
                   ) ▶₀ #i2 )
              case VoterAuthentication_VA_ReceiveAuthenticationComplete
              by contradiction /* cyclic */
            qed
          next
            case VoterAuthentication_VA_ReceiveAuthenticationResult_Ineligible
            by solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                            ~sk_voter.1, ~cid.1, ~token.1
                      ) ▶₀ #i2 )
          next
            case VoterAuthentication_VA_ReceiveAuthenticationResult_Unsuccessful
            by solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                            ~sk_voter.1, ~cid.1, ~token.1
                      ) ▶₀ #i2 )
          qed
        next
          case SecureChannel_Receive_case_3
          solve( VA_ReceiveAuthenticationResult_Trace( ~ec, ~va_id, res2, pseudo2,
                                                       pk2, bs2
                 ) @ #i2 )
            case VoterAuthentication_VA_ReceiveAuthenticationResult_Eligible
            solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                         ~sk_voter.1, ~cid.1, ~token.1
                   ) ▶₀ #i2 )
              case VoterAuthentication_VA_ReceiveAuthenticationComplete
              by contradiction /* cyclic */
            qed
          next
            case VoterAuthentication_VA_ReceiveAuthenticationResult_Ineligible
            by solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                            ~sk_voter.1, ~cid.1, ~token.1
                      ) ▶₀ #i2 )
          next
            case VoterAuthentication_VA_ReceiveAuthenticationResult_Unsuccessful
            by solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                            ~sk_voter.1, ~cid.1, ~token.1
                      ) ▶₀ #i2 )
          qed
        next
          case SecureChannel_Receive_case_4
          solve( VA_ReceiveAuthenticationResult_Trace( ~ec, ~va_id, res2, pseudo2,
                                                       pk2, bs2
                 ) @ #i2 )
            case VoterAuthentication_VA_ReceiveAuthenticationResult_Eligible
            solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                         ~sk_voter.1, ~cid.1, ~token.1
                   ) ▶₀ #i2 )
              case VoterAuthentication_VA_ReceiveAuthenticationComplete
              by contradiction /* cyclic */
            qed
          next
            case VoterAuthentication_VA_ReceiveAuthenticationResult_Ineligible
            by solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                            ~sk_voter.1, ~cid.1, ~token.1
                      ) ▶₀ #i2 )
          next
            case VoterAuthentication_VA_ReceiveAuthenticationResult_Unsuccessful
            by solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                            ~sk_voter.1, ~cid.1, ~token.1
                      ) ▶₀ #i2 )
          qed
        next
          case SecureChannel_Receive_case_5
          solve( VA_ReceiveAuthenticationResult_Trace( ~ec, ~va_id, res2, pseudo2,
                                                       pk2, bs2
                 ) @ #i2 )
            case VoterAuthentication_VA_ReceiveAuthenticationResult_Eligible
            solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                         ~sk_voter.1, ~cid.1, ~token.1
                   ) ▶₀ #i2 )
              case VoterAuthentication_VA_ReceiveAuthenticationComplete
              by contradiction /* cyclic */
            qed
          next
            case VoterAuthentication_VA_ReceiveAuthenticationResult_Ineligible
            by solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                            ~sk_voter.1, ~cid.1, ~token.1
                      ) ▶₀ #i2 )
          next
            case VoterAuthentication_VA_ReceiveAuthenticationResult_Unsuccessful
            by solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                            ~sk_voter.1, ~cid.1, ~token.1
                      ) ▶₀ #i2 )
          qed
        qed
      qed
    next
      case VoterAuthentication_VA_ReceiveAuthenticationResult_Ineligible
      solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V, ~sk_voter,
                                                   ~cid, ~token
             ) ▶₀ #i1 )
        case VoterAuthentication_VA_ReceiveAuthenticationComplete
        solve( SecureReceive( ~cid, <~ec, 'EAS'>, ~va_id,
                              <'EAS_Authentication_Result', 'ineligible', ~ec, pk(~sk_voter),
                               'ineligible'>
               ) ▶₁ #i1 )
          case SecureChannel_Receive_case_1
          solve( VA_ReceiveAuthenticationResult_Trace( ~ec, ~va_id, res2, pseudo2,
                                                       pk2, bs2
                 ) @ #i2 )
            case VoterAuthentication_VA_ReceiveAuthenticationResult_Eligible
            by solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                            ~sk_voter.1, ~cid.1, ~token.1
                      ) ▶₀ #i2 )
          next
            case VoterAuthentication_VA_ReceiveAuthenticationResult_Ineligible
            solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                         ~sk_voter.1, ~cid.1, ~token.1
                   ) ▶₀ #i2 )
              case VoterAuthentication_VA_ReceiveAuthenticationComplete
              by contradiction /* cyclic */
            qed
          next
            case VoterAuthentication_VA_ReceiveAuthenticationResult_Unsuccessful
            by solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                            ~sk_voter.1, ~cid.1, ~token.1
                      ) ▶₀ #i2 )
          qed
        next
          case SecureChannel_Receive_case_2
          solve( VA_ReceiveAuthenticationResult_Trace( ~ec, ~va_id, res2, pseudo2,
                                                       pk2, bs2
                 ) @ #i2 )
            case VoterAuthentication_VA_ReceiveAuthenticationResult_Eligible
            by solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                            ~sk_voter.1, ~cid.1, ~token.1
                      ) ▶₀ #i2 )
          next
            case VoterAuthentication_VA_ReceiveAuthenticationResult_Ineligible
            solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                         ~sk_voter.1, ~cid.1, ~token.1
                   ) ▶₀ #i2 )
              case VoterAuthentication_VA_ReceiveAuthenticationComplete
              by contradiction /* cyclic */
            qed
          next
            case VoterAuthentication_VA_ReceiveAuthenticationResult_Unsuccessful
            by solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                            ~sk_voter.1, ~cid.1, ~token.1
                      ) ▶₀ #i2 )
          qed
        next
          case SecureChannel_Receive_case_3
          solve( VA_ReceiveAuthenticationResult_Trace( ~ec, ~va_id, res2, pseudo2,
                                                       pk2, bs2
                 ) @ #i2 )
            case VoterAuthentication_VA_ReceiveAuthenticationResult_Eligible
            by solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                            ~sk_voter.1, ~cid.1, ~token.1
                      ) ▶₀ #i2 )
          next
            case VoterAuthentication_VA_ReceiveAuthenticationResult_Ineligible
            solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                         ~sk_voter.1, ~cid.1, ~token.1
                   ) ▶₀ #i2 )
              case VoterAuthentication_VA_ReceiveAuthenticationComplete
              by contradiction /* cyclic */
            qed
          next
            case VoterAuthentication_VA_ReceiveAuthenticationResult_Unsuccessful
            by solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                            ~sk_voter.1, ~cid.1, ~token.1
                      ) ▶₀ #i2 )
          qed
        next
          case SecureChannel_Receive_case_4
          solve( VA_ReceiveAuthenticationResult_Trace( ~ec, ~va_id, res2, pseudo2,
                                                       pk2, bs2
                 ) @ #i2 )
            case VoterAuthentication_VA_ReceiveAuthenticationResult_Eligible
            by solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                            ~sk_voter.1, ~cid.1, ~token.1
                      ) ▶₀ #i2 )
          next
            case VoterAuthentication_VA_ReceiveAuthenticationResult_Ineligible
            solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                         ~sk_voter.1, ~cid.1, ~token.1
                   ) ▶₀ #i2 )
              case VoterAuthentication_VA_ReceiveAuthenticationComplete
              by contradiction /* cyclic */
            qed
          next
            case VoterAuthentication_VA_ReceiveAuthenticationResult_Unsuccessful
            by solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                            ~sk_voter.1, ~cid.1, ~token.1
                      ) ▶₀ #i2 )
          qed
        next
          case SecureChannel_Receive_case_5
          solve( VA_ReceiveAuthenticationResult_Trace( ~ec, ~va_id, res2, pseudo2,
                                                       pk2, bs2
                 ) @ #i2 )
            case VoterAuthentication_VA_ReceiveAuthenticationResult_Eligible
            by solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                            ~sk_voter.1, ~cid.1, ~token.1
                      ) ▶₀ #i2 )
          next
            case VoterAuthentication_VA_ReceiveAuthenticationResult_Ineligible
            solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                         ~sk_voter.1, ~cid.1, ~token.1
                   ) ▶₀ #i2 )
              case VoterAuthentication_VA_ReceiveAuthenticationComplete
              by contradiction /* cyclic */
            qed
          next
            case VoterAuthentication_VA_ReceiveAuthenticationResult_Unsuccessful
            by solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                            ~sk_voter.1, ~cid.1, ~token.1
                      ) ▶₀ #i2 )
          qed
        qed
      qed
    next
      case VoterAuthentication_VA_ReceiveAuthenticationResult_Unsuccessful
      solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V, ~sk_voter,
                                                   ~cid, ~token
             ) ▶₀ #i1 )
        case VoterAuthentication_VA_ReceiveAuthenticationComplete
        solve( SecureReceive( ~cid, <~ec, 'EAS'>, ~va_id,
                              <'EAS_Authentication_Result', 'unsuccessful', ~ec, pk(~sk_voter),
                               'ineligible'>
               ) ▶₁ #i1 )
          case SecureChannel_Receive_case_1
          solve( VA_ReceiveAuthenticationResult_Trace( ~ec, ~va_id, res2, pseudo2,
                                                       pk2, bs2
                 ) @ #i2 )
            case VoterAuthentication_VA_ReceiveAuthenticationResult_Eligible
            by solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                            ~sk_voter.1, ~cid.1, ~token.1
                      ) ▶₀ #i2 )
          next
            case VoterAuthentication_VA_ReceiveAuthenticationResult_Ineligible
            by solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                            ~sk_voter.1, ~cid.1, ~token.1
                      ) ▶₀ #i2 )
          next
            case VoterAuthentication_VA_ReceiveAuthenticationResult_Unsuccessful
            solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                         ~sk_voter.1, ~cid.1, ~token.1
                   ) ▶₀ #i2 )
              case VoterAuthentication_VA_ReceiveAuthenticationComplete
              by contradiction /* cyclic */
            qed
          qed
        next
          case SecureChannel_Receive_case_2
          solve( VA_ReceiveAuthenticationResult_Trace( ~ec, ~va_id, res2, pseudo2,
                                                       pk2, bs2
                 ) @ #i2 )
            case VoterAuthentication_VA_ReceiveAuthenticationResult_Eligible
            by solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                            ~sk_voter.1, ~cid.1, ~token.1
                      ) ▶₀ #i2 )
          next
            case VoterAuthentication_VA_ReceiveAuthenticationResult_Ineligible
            by solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                            ~sk_voter.1, ~cid.1, ~token.1
                      ) ▶₀ #i2 )
          next
            case VoterAuthentication_VA_ReceiveAuthenticationResult_Unsuccessful
            solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                         ~sk_voter.1, ~cid.1, ~token.1
                   ) ▶₀ #i2 )
              case VoterAuthentication_VA_ReceiveAuthenticationComplete
              by contradiction /* cyclic */
            qed
          qed
        next
          case SecureChannel_Receive_case_3
          solve( VA_ReceiveAuthenticationResult_Trace( ~ec, ~va_id, res2, pseudo2,
                                                       pk2, bs2
                 ) @ #i2 )
            case VoterAuthentication_VA_ReceiveAuthenticationResult_Eligible
            by solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                            ~sk_voter.1, ~cid.1, ~token.1
                      ) ▶₀ #i2 )
          next
            case VoterAuthentication_VA_ReceiveAuthenticationResult_Ineligible
            by solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                            ~sk_voter.1, ~cid.1, ~token.1
                      ) ▶₀ #i2 )
          next
            case VoterAuthentication_VA_ReceiveAuthenticationResult_Unsuccessful
            solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                         ~sk_voter.1, ~cid.1, ~token.1
                   ) ▶₀ #i2 )
              case VoterAuthentication_VA_ReceiveAuthenticationComplete
              by contradiction /* cyclic */
            qed
          qed
        next
          case SecureChannel_Receive_case_4
          solve( VA_ReceiveAuthenticationResult_Trace( ~ec, ~va_id, res2, pseudo2,
                                                       pk2, bs2
                 ) @ #i2 )
            case VoterAuthentication_VA_ReceiveAuthenticationResult_Eligible
            by solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                            ~sk_voter.1, ~cid.1, ~token.1
                      ) ▶₀ #i2 )
          next
            case VoterAuthentication_VA_ReceiveAuthenticationResult_Ineligible
            by solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                            ~sk_voter.1, ~cid.1, ~token.1
                      ) ▶₀ #i2 )
          next
            case VoterAuthentication_VA_ReceiveAuthenticationResult_Unsuccessful
            solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                         ~sk_voter.1, ~cid.1, ~token.1
                   ) ▶₀ #i2 )
              case VoterAuthentication_VA_ReceiveAuthenticationComplete
              by contradiction /* cyclic */
            qed
          qed
        next
          case SecureChannel_Receive_case_5
          solve( VA_ReceiveAuthenticationResult_Trace( ~ec, ~va_id, res2, pseudo2,
                                                       pk2, bs2
                 ) @ #i2 )
            case VoterAuthentication_VA_ReceiveAuthenticationResult_Eligible
            by solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                            ~sk_voter.1, ~cid.1, ~token.1
                      ) ▶₀ #i2 )
          next
            case VoterAuthentication_VA_ReceiveAuthenticationResult_Ineligible
            by solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                            ~sk_voter.1, ~cid.1, ~token.1
                      ) ▶₀ #i2 )
          next
            case VoterAuthentication_VA_ReceiveAuthenticationResult_Unsuccessful
            solve( VA_State_ReceiveAuthenticationResult( ~ec, ~va_id, $V.1,
                                                         ~sk_voter.1, ~cid.1, ~token.1
                   ) ▶₀ #i2 )
              case VoterAuthentication_VA_ReceiveAuthenticationComplete
              by contradiction /* cyclic */
            qed
          qed
        qed
      qed
    qed
  qed
qed
