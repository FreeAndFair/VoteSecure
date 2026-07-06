simplify
solve( !BB_Root( ~ec, ~bbid, ~ec, root_eid_unused ) ▶₂ #i1 )
  case BulletinBoard_Create
  solve( !BB_Root( ~ec, ~bbid.1, ~ec, root_eid_unused ) ▶₂ #i2 )
    case BulletinBoard_Create
    solve( !BB_Entry( ~bbid, tracker1,
                      <'BBEntry_Ballot_Submission', ~ec, timestamp,
                       <'VA_Submit_Ballot', ~ec, cryptograms1, signed_voter_auth>,
                       sign(<'VA_Submit_Ballot', ~ec, cryptograms1, signed_voter_auth>, '1',
                            ~sk_voter)
                      >,
                      prev_unused
           ) ▶₃ #i1 )
      case BulletinBoard_Append
      solve( !BB_Entry( ~bbid, tracker2,
                        <'BBEntry_Ballot_Submission', ~ec, timestamp.1,
                         <'VA_Submit_Ballot', ~ec, cryptograms2, signed_voter_auth.1>,
                         sign(<'VA_Submit_Ballot', ~ec, cryptograms2, signed_voter_auth.1>, '1',
                              ~sk_voter.1)
                        >,
                        prev_unused.1
             ) ▶₃ #i2 )
        case BulletinBoard_Append
        solve( BB_Append_Request( ~bbid,
                                  <'BBEntry_Ballot_Submission', ~ec, timestamp,
                                   <'VA_Submit_Ballot', ~ec, cryptograms1, signed_voter_auth>,
                                   sign(<'VA_Submit_Ballot', ~ec, cryptograms1, signed_voter_auth>, '1',
                                        ~sk_voter)
                                  >,
                                  prev_unused
               ) ▶₂ #vr.10 )
          case BallotSubmission_DBB_AppendSubmittedBallot_case_1
          solve( BB_Append_Request( ~bbid,
                                    <'BBEntry_Ballot_Submission', ~ec, timestamp,
                                     <'VA_Submit_Ballot', ~ec, cryptograms2, signed_voter_auth>,
                                     sign(<'VA_Submit_Ballot', ~ec, cryptograms2, signed_voter_auth>, '1',
                                          ~sk_voter.1)
                                    >,
                                    prev_unused
                 ) ▶₂ #vr.11 )
            case BallotSubmission_DBB_AppendSubmittedBallot_case_2
            solve( BB_Append_Request( ~bbid, e_unused, prev_prev_unused ) ▶₂ #vr.16 )
              case BallotSubmission_DBB_AppendSubmittedBallot_case_1
              solve( BB_Current( ~bbid, ~root_eid ) ▶₁ #vr.10 )
                case BulletinBoard_Create
                solve( BB_Current( ~bbid, ~new_eid ) ▶₁ #vr.11 )
                  case BulletinBoard_Append
                  solve( VA_State_BallotSubmitResponse( ~ec, ~va_id, ~cid, $V, ~ballot,
                                                        <ny_encrypt_c1(x, x.1, x.2),
                                                         ny_encrypt_c2(x, x.1, x.2), ny_encrypt_p(x, x.1, x.2)
                                                        >,
                                                        ~r
                         ) ▶₀ #i1 )
                    case BallotSubmission_VA_PresentBallot
                    solve( !VA_Eligible_Voter( ~ec, ~va_id, pseudo1, ~sk_voter,
                                               ballot_style1,
                                               <
                                                <'VoterAuthorization', ~ec, pseudo, pk_voter, ballot_style, ts
                                                >,
                                                sign(<'VoterAuthorization', ~ec, pseudo, pk_voter,
                                                      ballot_style, ts>,
                                                     x, ~sk_eas)
                                               >
                           ) ▶₁ #i1 )
                      case Mock_Voter_Authentication
                      solve( VA_State_BallotSubmitResponse( ~ec, ~va_id.1, ~cid.1, $V.1,
                                                            ~ballot.1,
                                                            <ny_encrypt_c1(x, x.1, x.2),
                                                             ny_encrypt_c2(x, x.1, x.2),
                                                             ny_encrypt_p(x, x.1, x.2)>,
                                                            ~r.1
                             ) ▶₀ #i2 )
                        case BallotSubmission_VA_PresentBallot
                        solve( !VA_Eligible_Voter( ~ec, ~va_id.1, pseudo2, ~sk_voter.1,
                                                   ballot_style2,
                                                   <
                                                    <'VoterAuthorization', ~ec, pseudo, pk_voter,
                                                     ballot_style, ts.2>,
                                                    sign(<'VoterAuthorization', ~ec, pseudo, pk_voter,
                                                          ballot_style, ts.2>,
                                                         x, ~sk_eas)
                                                   >
                               ) ▶₁ #i2 )
                          case Mock_Voter_Authentication
                          solve( SecureReceive( ~cid, <~ec, 'DBB'>, ~va_id,
                                                <'DBB_Ballot_Tracker', ~ec, ~new_eid>
                                 ) ▶₄ #i1 )
                            case SecureChannel_Receive_case_1
                            solve( SecureReceive( ~cid.1, <~ec, 'DBB'>, ~va_id.1,
                                                  <'DBB_Ballot_Tracker', ~ec, ~new_eid.1>
                                   ) ▶₄ #i2 )
                              case SecureChannel_Receive_case_1
                              solve( SecureReceive( ~cid, ~va_id, <~ec, 'DBB'>,
                                                    <
                                                     <'VA_Submit_Ballot', ~ec,
                                                      <ny_encrypt_c1(~ballot, pk(~sk_election), ~r),
                                                       ny_encrypt_c2(~ballot, pk(~sk_election), ~r),
                                                       ny_encrypt_p(~ballot, pk(~sk_election), ~r)>,
                                                      <'VoterAuthorization', ~ec, pseudonym($V),
                                                       pk(~sk_voter), ~bs, ~ts>,
                                                      sign(<'VoterAuthorization', ~ec, pseudonym($V),
                                                            pk(~sk_voter), ~bs, ~ts>,
                                                           '1', ~sk_eas)
                                                     >,
                                                     sign(<'VA_Submit_Ballot', ~ec,
                                                           <ny_encrypt_c1(~ballot, pk(~sk_election), ~r),
                                                            ny_encrypt_c2(~ballot, pk(~sk_election), ~r),
                                                            ny_encrypt_p(~ballot, pk(~sk_election), ~r)>,
                                                           <'VoterAuthorization', ~ec, pseudonym($V),
                                                            pk(~sk_voter), ~bs, ~ts>,
                                                           sign(<'VoterAuthorization', ~ec, pseudonym($V),
                                                                 pk(~sk_voter), ~bs, ~ts>,
                                                                '1', ~sk_eas)
                                                          >,
                                                          '1', ~sk_voter)
                                                    >
                                     ) ▶₁ #vr.13 )
                                case SecureChannel_Receive_case_1
                                solve( SecureReceive( ~cid.1, ~va_id.1, <~ec, 'DBB'>,
                                                      <
                                                       <'VA_Submit_Ballot', ~ec,
                                                        <ny_encrypt_c1(~ballot.1, pk(~sk_election), ~r.1),
                                                         ny_encrypt_c2(~ballot.1, pk(~sk_election), ~r.1),
                                                         ny_encrypt_p(~ballot.1, pk(~sk_election), ~r.1)>,
                                                        <'VoterAuthorization', ~ec, pseudonym($V.1),
                                                         pk(~sk_voter.1), ~bs.1, ~ts.2>,
                                                        sign(<'VoterAuthorization', ~ec, pseudonym($V.1),
                                                              pk(~sk_voter.1), ~bs.1, ~ts.2>,
                                                             '1', ~sk_eas)
                                                       >,
                                                       sign(<'VA_Submit_Ballot', ~ec,
                                                             <
                                                              ny_encrypt_c1(~ballot.1, pk(~sk_election),
                                                                            ~r.1),
                                                              ny_encrypt_c2(~ballot.1, pk(~sk_election),
                                                                            ~r.1),
                                                              ny_encrypt_p(~ballot.1, pk(~sk_election), ~r.1)
                                                             >,
                                                             <'VoterAuthorization', ~ec, pseudonym($V.1),
                                                              pk(~sk_voter.1), ~bs.1, ~ts.2>,
                                                             sign(<'VoterAuthorization', ~ec,
                                                                   pseudonym($V.1), pk(~sk_voter.1), ~bs.1,
                                                                   ~ts.2>,
                                                                  '1', ~sk_eas)
                                                            >,
                                                            '1', ~sk_voter.1)
                                                      >
                                       ) ▶₁ #vr.15 )
                                  case SecureChannel_Receive_case_1
                                  solve( (#i1 < #i2)  ∥ (#i2 < #i1) )
                                    case case_1
                                    solve( (~bs_unused = ~bs)  ∥ (~bs_unused = ~bs.1) )
                                      case case_1
                                      solve( (~bs_unused = ~bs)  ∥ (~bs_unused = ~bs.1) )
                                        case case_1
                                        solve( (~ev_bs_unused = ~bs)  ∥ (~ev_bs_unused = ~bs.1) )
                                          case case_1
                                          solve( (~ev_bs_unused = ~bs)  ∥ (~ev_bs_unused = ~bs.1) )
                                            case case_1
                                            solve( ($EV = $V)  ∥ ($EV = $V.1) )
                                              case case_1
                                              solve( ($EV.1 = $EV)  ∥ ($EV.1 = $V) )
                                                case case_1
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
    qed
  qed
qed
