simplify
solve( VA_State_BallotCastResponse( ~ec, ~va_id, ~cid, pseudo1, ~ballot,
                                    cryptograms1, ~r, ~new_eid
       ) ▶₀ #i1 )
  case BallotCast_VA_Cast_case_1
  solve( !VA_Eligible_Voter( ~ec, ~va_id, pseudonym($V), ~sk_voter,
                             ~bs_unused, signed_voter_auth
         ) ▶₁ #i1 )
    case Mock_Voter_Authentication
    solve( !BB_Root( ~ec, ~bbid, r_unused, root_eid_unused ) ▶₂ #i1 )
      case BulletinBoard_Create
      solve( !BB_Entry( ~bbid, ~new_eid, sub_bb_entry_unused, prev_sub_unused
             ) ▶₃ #i1 )
        case BulletinBoard_Append
        solve( !BB_Entry( ~bbid, ~new_eid.1,
                          <'BBEntry_Ballot_Cast', ts_cast,
                           <
                            <'VA_Submit_Ballot', ~ec,
                             <ny_encrypt_c1(~ballot, pk(~sk_election), ~r),
                              ny_encrypt_c2(~ballot, pk(~sk_election), ~r),
                              ny_encrypt_p(~ballot, pk(~sk_election), ~r)>,
                             <'VoterAuthorization', ~ec, pseudonym($V), pk(~sk_voter), ~bs_unused, ~ts
                             >,
                             sign(<'VoterAuthorization', ~ec, pseudonym($V), pk(~sk_voter),
                                   ~bs_unused, ~ts>,
                                  '1', ~sk_eas)
                            >,
                            sign(<'VA_Submit_Ballot', ~ec,
                                  <ny_encrypt_c1(~ballot, pk(~sk_election), ~r),
                                   ny_encrypt_c2(~ballot, pk(~sk_election), ~r),
                                   ny_encrypt_p(~ballot, pk(~sk_election), ~r)>,
                                  <'VoterAuthorization', ~ec, pseudonym($V), pk(~sk_voter), ~bs_unused, ~ts
                                  >,
                                  sign(<'VoterAuthorization', ~ec, pseudonym($V), pk(~sk_voter),
                                        ~bs_unused, ~ts>,
                                       '1', ~sk_eas)
                                 >,
                                 '1', ~sk_voter)
                           >,
                           <'VA_Cast_Ballot', ~ec, tracker,
                            <'VoterAuthorization', ~ec, pseudonym($V), pk(~sk_voter), ~bs_unused, ~ts
                            >,
                            sign(<'VoterAuthorization', ~ec, pseudonym($V), pk(~sk_voter),
                                  ~bs_unused, ~ts>,
                                 '1', ~sk_eas)
                           >,
                           sign(<'VA_Cast_Ballot', ~ec, tracker,
                                 <'VoterAuthorization', ~ec, pseudonym($V), pk(~sk_voter), ~bs_unused, ~ts
                                 >,
                                 sign(<'VoterAuthorization', ~ec, pseudonym($V), pk(~sk_voter),
                                       ~bs_unused, ~ts>,
                                      '1', ~sk_eas)
                                >,
                                '1', ~sk_voter)
                          >,
                          prev_cast_unused
               ) ▶₄ #i1 )
          case BulletinBoard_Append
          solve( SecureReceive( ~cid, <~ec, 'DBB'>, ~va_id,
                                <'DBB_Cast_Confirmation', ~ec, ~new_eid, ~new_eid.1>
                 ) ▶₅ #i1 )
            case SecureChannel_Receive_case_2
            solve( VA_State_BallotCastResponse( ~ec, ~va_id.1, ~cid.1, pseudo2,
                                                ~ballot.1, cryptograms2, ~r.1, ~new_eid.2
                   ) ▶₀ #i2 )
              case BallotCast_VA_Cast_case_2
              solve( !VA_Eligible_Voter( ~ec, ~va_id.1, pseudonym($V.1), ~sk_voter.1,
                                         ~bs_unused.1, signed_voter_auth
                     ) ▶₁ #i2 )
                case Mock_Voter_Authentication
                solve( !BB_Root( ~ec, ~bbid.1, r_unused, root_eid_unused ) ▶₂ #i2 )
                  case BulletinBoard_Create
                  solve( !BB_Entry( ~bbid, ~new_eid.2, sub_bb_entry_unused, prev_sub_unused
                         ) ▶₃ #i2 )
                    case BulletinBoard_Append
                    solve( !BB_Entry( ~bbid, ~new_eid.3,
                                      <'BBEntry_Ballot_Cast', ts_cast,
                                       <
                                        <'VA_Submit_Ballot', ~ec,
                                         <ny_encrypt_c1(~ballot.1, pk(~sk_election), ~r.1),
                                          ny_encrypt_c2(~ballot.1, pk(~sk_election), ~r.1),
                                          ny_encrypt_p(~ballot.1, pk(~sk_election), ~r.1)>,
                                         <'VoterAuthorization', ~ec, pseudonym($V.1), pk(~sk_voter.1),
                                          ~bs_unused.1, ~ts.3>,
                                         sign(<'VoterAuthorization', ~ec, pseudonym($V.1), pk(~sk_voter.1),
                                               ~bs_unused.1, ~ts.3>,
                                              '1', ~sk_eas)
                                        >,
                                        sign(<'VA_Submit_Ballot', ~ec,
                                              <ny_encrypt_c1(~ballot.1, pk(~sk_election), ~r.1),
                                               ny_encrypt_c2(~ballot.1, pk(~sk_election), ~r.1),
                                               ny_encrypt_p(~ballot.1, pk(~sk_election), ~r.1)>,
                                              <'VoterAuthorization', ~ec, pseudonym($V.1), pk(~sk_voter.1),
                                               ~bs_unused.1, ~ts.3>,
                                              sign(<'VoterAuthorization', ~ec, pseudonym($V.1),
                                                    pk(~sk_voter.1), ~bs_unused.1, ~ts.3>,
                                                   '1', ~sk_eas)
                                             >,
                                             '1', ~sk_voter.1)
                                       >,
                                       <'VA_Cast_Ballot', ~ec, tracker,
                                        <'VoterAuthorization', ~ec, pseudonym($V.1), pk(~sk_voter.1),
                                         ~bs_unused.1, ~ts.3>,
                                        sign(<'VoterAuthorization', ~ec, pseudonym($V.1), pk(~sk_voter.1),
                                              ~bs_unused.1, ~ts.3>,
                                             '1', ~sk_eas)
                                       >,
                                       sign(<'VA_Cast_Ballot', ~ec, tracker,
                                             <'VoterAuthorization', ~ec, pseudonym($V.1), pk(~sk_voter.1),
                                              ~bs_unused.1, ~ts.3>,
                                             sign(<'VoterAuthorization', ~ec, pseudonym($V.1),
                                                   pk(~sk_voter.1), ~bs_unused.1, ~ts.3>,
                                                  '1', ~sk_eas)
                                            >,
                                            '1', ~sk_voter.1)
                                      >,
                                      prev_cast_unused
                           ) ▶₄ #i2 )
                      case BulletinBoard_Append
                      solve( SecureReceive( ~cid.1, <~ec, 'DBB'>, ~va_id.1,
                                            <'DBB_Cast_Confirmation', ~ec, ~new_eid.2, ~new_eid.3>
                             ) ▶₅ #i2 )
                        case SecureChannel_Receive_case_2
                        solve( BB_Trace_Entry( ~bbid, ~root_eid, ~ec, 'root' ) @ #t_root )
                          case BulletinBoard_Create
                          solve( BB_Trace_Entry( ~bbid, ~new_eid,
                                                 <'BBEntry_Ballot_Submission', ~ec, ~ts.1,
                                                  <'VA_Submit_Ballot', ~ec,
                                                   <ny_encrypt_c1(~ballot, pk(~sk_election), ~r),
                                                    ny_encrypt_c2(~ballot, pk(~sk_election), ~r),
                                                    ny_encrypt_p(~ballot, pk(~sk_election), ~r)>,
                                                   <'VoterAuthorization', ~ec, pseudonym($V), pk(~sk_voter),
                                                    ~bs_unused, ~ts>,
                                                   sign(<'VoterAuthorization', ~ec, pseudonym($V),
                                                         pk(~sk_voter), ~bs_unused, ~ts>,
                                                        '1', ~sk_eas)
                                                  >,
                                                  sign(<'VA_Submit_Ballot', ~ec,
                                                        <ny_encrypt_c1(~ballot, pk(~sk_election), ~r),
                                                         ny_encrypt_c2(~ballot, pk(~sk_election), ~r),
                                                         ny_encrypt_p(~ballot, pk(~sk_election), ~r)>,
                                                        <'VoterAuthorization', ~ec, pseudonym($V),
                                                         pk(~sk_voter), ~bs_unused, ~ts>,
                                                        sign(<'VoterAuthorization', ~ec, pseudonym($V),
                                                              pk(~sk_voter), ~bs_unused, ~ts>,
                                                             '1', ~sk_eas)
                                                       >,
                                                       '1', ~sk_voter)
                                                 >,
                                                 ~root_eid
                                 ) @ #t_adv1 )
                            case BulletinBoard_Append
                            solve( BB_Trace_Entry( ~bbid, ~new_eid.2,
                                                   <'BBEntry_Ballot_Submission', ~ec, ~ts.4,
                                                    <'VA_Submit_Ballot', ~ec,
                                                     <ny_encrypt_c1(~ballot.1, pk(~sk_election), ~r.1),
                                                      ny_encrypt_c2(~ballot.1, pk(~sk_election), ~r.1),
                                                      ny_encrypt_p(~ballot.1, pk(~sk_election), ~r.1)>,
                                                     <'VoterAuthorization', ~ec, pseudonym($V.1),
                                                      pk(~sk_voter.1), ~bs_unused.1, ~ts.3>,
                                                     sign(<'VoterAuthorization', ~ec, pseudonym($V.1),
                                                           pk(~sk_voter.1), ~bs_unused.1, ~ts.3>,
                                                          '1', ~sk_eas)
                                                    >,
                                                    sign(<'VA_Submit_Ballot', ~ec,
                                                          <ny_encrypt_c1(~ballot.1, pk(~sk_election), ~r.1),
                                                           ny_encrypt_c2(~ballot.1, pk(~sk_election), ~r.1),
                                                           ny_encrypt_p(~ballot.1, pk(~sk_election), ~r.1)>,
                                                          <'VoterAuthorization', ~ec, pseudonym($V.1),
                                                           pk(~sk_voter.1), ~bs_unused.1, ~ts.3>,
                                                          sign(<'VoterAuthorization', ~ec, pseudonym($V.1),
                                                                pk(~sk_voter.1), ~bs_unused.1, ~ts.3>,
                                                               '1', ~sk_eas)
                                                         >,
                                                         '1', ~sk_voter.1)
                                                   >,
                                                   ~new_eid
                                   ) @ #t_adv2 )
                              case BulletinBoard_Append
                              solve( BB_Current( ~bbid, ~root_eid ) ▶₁ #t_adv1 )
                                case BulletinBoard_Create
                                solve( BB_Append_Request( ~bbid,
                                                          <'BBEntry_Ballot_Submission', ~ec, ~ts.1,
                                                           <'VA_Submit_Ballot', ~ec,
                                                            <ny_encrypt_c1(~ballot, pk(~sk_election), ~r),
                                                             ny_encrypt_c2(~ballot, pk(~sk_election), ~r),
                                                             ny_encrypt_p(~ballot, pk(~sk_election), ~r)>,
                                                            <'VoterAuthorization', ~ec, pseudonym($V),
                                                             pk(~sk_voter), ~bs_unused, ~ts>,
                                                            sign(<'VoterAuthorization', ~ec, pseudonym($V),
                                                                  pk(~sk_voter), ~bs_unused, ~ts>,
                                                                 '1', ~sk_eas)
                                                           >,
                                                           sign(<'VA_Submit_Ballot', ~ec,
                                                                 <
                                                                  ny_encrypt_c1(~ballot, pk(~sk_election),
                                                                                ~r),
                                                                  ny_encrypt_c2(~ballot, pk(~sk_election),
                                                                                ~r),
                                                                  ny_encrypt_p(~ballot, pk(~sk_election), ~r)
                                                                 >,
                                                                 <'VoterAuthorization', ~ec, pseudonym($V),
                                                                  pk(~sk_voter), ~bs_unused, ~ts>,
                                                                 sign(<'VoterAuthorization', ~ec,
                                                                       pseudonym($V), pk(~sk_voter),
                                                                       ~bs_unused, ~ts>,
                                                                      '1', ~sk_eas)
                                                                >,
                                                                '1', ~sk_voter)
                                                          >,
                                                          ~root_eid
                                       ) ▶₂ #t_adv1 )
                                  case Mock_AppendSubmittedBallot
                                  solve( BB_Current( ~bbid, ~new_eid ) ▶₁ #t_adv2 )
                                    case BulletinBoard_Append
                                    solve( BB_Append_Request( ~bbid,
                                                              <'BBEntry_Ballot_Submission', ~ec, ~ts.4,
                                                               <'VA_Submit_Ballot', ~ec,
                                                                <
                                                                 ny_encrypt_c1(~ballot.1, pk(~sk_election),
                                                                               ~r.1),
                                                                 ny_encrypt_c2(~ballot.1, pk(~sk_election),
                                                                               ~r.1),
                                                                 ny_encrypt_p(~ballot.1, pk(~sk_election),
                                                                              ~r.1)
                                                                >,
                                                                <'VoterAuthorization', ~ec, pseudonym($V.1),
                                                                 pk(~sk_voter.1), ~bs_unused.1, ~ts.3>,
                                                                sign(<'VoterAuthorization', ~ec,
                                                                      pseudonym($V.1), pk(~sk_voter.1),
                                                                      ~bs_unused.1, ~ts.3>,
                                                                     '1', ~sk_eas)
                                                               >,
                                                               sign(<'VA_Submit_Ballot', ~ec,
                                                                     <
                                                                      ny_encrypt_c1(~ballot.1,
                                                                                    pk(~sk_election), ~r.1),
                                                                      ny_encrypt_c2(~ballot.1,
                                                                                    pk(~sk_election), ~r.1),
                                                                      ny_encrypt_p(~ballot.1,
                                                                                   pk(~sk_election), ~r.1)
                                                                     >,
                                                                     <'VoterAuthorization', ~ec,
                                                                      pseudonym($V.1), pk(~sk_voter.1),
                                                                      ~bs_unused.1, ~ts.3>,
                                                                     sign(<'VoterAuthorization', ~ec,
                                                                           pseudonym($V.1), pk(~sk_voter.1),
                                                                           ~bs_unused.1, ~ts.3>,
                                                                          '1', ~sk_eas)
                                                                    >,
                                                                    '1', ~sk_voter.1)
                                                              >,
                                                              ~new_eid
                                           ) ▶₂ #t_adv2 )
                                      case Mock_AppendSubmittedBallot
                                      solve( BB_Current( ~bbid, ~new_eid.2 ) ▶₁ #t_adv3 )
                                        case BulletinBoard_Append
                                        solve( BB_Append_Request( ~bbid,
                                                                  <'BBEntry_Ballot_Cast', ~ts.2,
                                                                   <
                                                                    <'VA_Submit_Ballot', ~ec,
                                                                     <
                                                                      ny_encrypt_c1(~ballot, pk(~sk_election),
                                                                                    ~r),
                                                                      ny_encrypt_c2(~ballot, pk(~sk_election),
                                                                                    ~r),
                                                                      ny_encrypt_p(~ballot, pk(~sk_election),
                                                                                   ~r)
                                                                     >,
                                                                     <'VoterAuthorization', ~ec,
                                                                      pseudonym($V), pk(~sk_voter),
                                                                      ~bs_unused, ~ts>,
                                                                     sign(<'VoterAuthorization', ~ec,
                                                                           pseudonym($V), pk(~sk_voter),
                                                                           ~bs_unused, ~ts>,
                                                                          '1', ~sk_eas)
                                                                    >,
                                                                    sign(<'VA_Submit_Ballot', ~ec,
                                                                          <
                                                                           ny_encrypt_c1(~ballot,
                                                                                         pk(~sk_election),
                                                                                         ~r),
                                                                           ny_encrypt_c2(~ballot,
                                                                                         pk(~sk_election),
                                                                                         ~r),
                                                                           ny_encrypt_p(~ballot,
                                                                                        pk(~sk_election), ~r)
                                                                          >,
                                                                          <'VoterAuthorization', ~ec,
                                                                           pseudonym($V), pk(~sk_voter),
                                                                           ~bs_unused, ~ts>,
                                                                          sign(<'VoterAuthorization', ~ec,
                                                                                pseudonym($V), pk(~sk_voter),
                                                                                ~bs_unused, ~ts>,
                                                                               '1', ~sk_eas)
                                                                         >,
                                                                         '1', ~sk_voter)
                                                                   >,
                                                                   <'VA_Cast_Ballot', ~ec, ~new_eid,
                                                                    <'VoterAuthorization', ~ec,
                                                                     pseudonym($V), pk(~sk_voter),
                                                                     ~bs_unused, ~ts>,
                                                                    sign(<'VoterAuthorization', ~ec,
                                                                          pseudonym($V), pk(~sk_voter),
                                                                          ~bs_unused, ~ts>,
                                                                         '1', ~sk_eas)
                                                                   >,
                                                                   sign(<'VA_Cast_Ballot', ~ec, ~new_eid,
                                                                         <'VoterAuthorization', ~ec,
                                                                          pseudonym($V), pk(~sk_voter),
                                                                          ~bs_unused, ~ts>,
                                                                         sign(<'VoterAuthorization', ~ec,
                                                                               pseudonym($V), pk(~sk_voter),
                                                                               ~bs_unused, ~ts>,
                                                                              '1', ~sk_eas)
                                                                        >,
                                                                        '1', ~sk_voter)
                                                                  >,
                                                                  ~new_eid.2
                                               ) ▶₂ #t_adv3 )
                                          case BallotCast_DBB_AppendCastBallot
                                          solve( BB_Current( ~bbid, ~new_eid.1 ) ▶₁ #t_adv4 )
                                            case BulletinBoard_Append
                                            solve( BB_Append_Request( ~bbid,
                                                                      <'BBEntry_Ballot_Cast', ~ts.5,
                                                                       <
                                                                        <'VA_Submit_Ballot', ~ec,
                                                                         <
                                                                          ny_encrypt_c1(~ballot.1,
                                                                                        pk(~sk_election),
                                                                                        ~r.1),
                                                                          ny_encrypt_c2(~ballot.1,
                                                                                        pk(~sk_election),
                                                                                        ~r.1),
                                                                          ny_encrypt_p(~ballot.1,
                                                                                       pk(~sk_election), ~r.1)
                                                                         >,
                                                                         <'VoterAuthorization', ~ec,
                                                                          pseudonym($V.1), pk(~sk_voter.1),
                                                                          ~bs_unused.1, ~ts.3>,
                                                                         sign(<'VoterAuthorization', ~ec,
                                                                               pseudonym($V.1),
                                                                               pk(~sk_voter.1), ~bs_unused.1,
                                                                               ~ts.3>,
                                                                              '1', ~sk_eas)
                                                                        >,
                                                                        sign(<'VA_Submit_Ballot', ~ec,
                                                                              <
                                                                               ny_encrypt_c1(~ballot.1,
                                                                                             pk(~sk_election),
                                                                                             ~r.1),
                                                                               ny_encrypt_c2(~ballot.1,
                                                                                             pk(~sk_election),
                                                                                             ~r.1),
                                                                               ny_encrypt_p(~ballot.1,
                                                                                            pk(~sk_election),
                                                                                            ~r.1)
                                                                              >,
                                                                              <'VoterAuthorization', ~ec,
                                                                               pseudonym($V.1),
                                                                               pk(~sk_voter.1), ~bs_unused.1,
                                                                               ~ts.3>,
                                                                              sign(<'VoterAuthorization',
                                                                                    ~ec, pseudonym($V.1),
                                                                                    pk(~sk_voter.1),
                                                                                    ~bs_unused.1, ~ts.3>,
                                                                                   '1', ~sk_eas)
                                                                             >,
                                                                             '1', ~sk_voter.1)
                                                                       >,
                                                                       <'VA_Cast_Ballot', ~ec, ~new_eid.2,
                                                                        <'VoterAuthorization', ~ec,
                                                                         pseudonym($V.1), pk(~sk_voter.1),
                                                                         ~bs_unused.1, ~ts.3>,
                                                                        sign(<'VoterAuthorization', ~ec,
                                                                              pseudonym($V.1),
                                                                              pk(~sk_voter.1), ~bs_unused.1,
                                                                              ~ts.3>,
                                                                             '1', ~sk_eas)
                                                                       >,
                                                                       sign(<'VA_Cast_Ballot', ~ec,
                                                                             ~new_eid.2,
                                                                             <'VoterAuthorization', ~ec,
                                                                              pseudonym($V.1),
                                                                              pk(~sk_voter.1), ~bs_unused.1,
                                                                              ~ts.3>,
                                                                             sign(<'VoterAuthorization', ~ec,
                                                                                   pseudonym($V.1),
                                                                                   pk(~sk_voter.1),
                                                                                   ~bs_unused.1, ~ts.3>,
                                                                                  '1', ~sk_eas)
                                                                            >,
                                                                            '1', ~sk_voter.1)
                                                                      >,
                                                                      ~new_eid.1
                                                   ) ▶₂ #t_adv4 )
                                              case BallotCast_DBB_AppendCastBallot
                                              solve( SecureReceive( ~cid, ~va_id, <~ec, 'DBB'>,
                                                                    <
                                                                     <'VA_Cast_Ballot', ~ec, ~new_eid,
                                                                      <'VoterAuthorization', ~ec,
                                                                       pseudonym($V), pk(~sk_voter),
                                                                       ~bs_unused, ~ts>,
                                                                      sign(<'VoterAuthorization', ~ec,
                                                                            pseudonym($V), pk(~sk_voter),
                                                                            ~bs_unused, ~ts>,
                                                                           '1', ~sk_eas)
                                                                     >,
                                                                     sign(<'VA_Cast_Ballot', ~ec, ~new_eid,
                                                                           <'VoterAuthorization', ~ec,
                                                                            pseudonym($V), pk(~sk_voter),
                                                                            ~bs_unused, ~ts>,
                                                                           sign(<'VoterAuthorization', ~ec,
                                                                                 pseudonym($V),
                                                                                 pk(~sk_voter), ~bs_unused,
                                                                                 ~ts>,
                                                                                '1', ~sk_eas)
                                                                          >,
                                                                          '1', ~sk_voter)
                                                                    >
                                                     ) ▶₃ #vr.20 )
                                                case SecureChannel_Receive_case_1
                                                solve( SecureReceive( ~cid.1, ~va_id.1, <~ec, 'DBB'>,
                                                                      <
                                                                       <'VA_Cast_Ballot', ~ec, ~new_eid.2,
                                                                        <'VoterAuthorization', ~ec,
                                                                         pseudonym($V.1), pk(~sk_voter.1),
                                                                         ~bs_unused.1, ~ts.3>,
                                                                        sign(<'VoterAuthorization', ~ec,
                                                                              pseudonym($V.1),
                                                                              pk(~sk_voter.1), ~bs_unused.1,
                                                                              ~ts.3>,
                                                                             '1', ~sk_eas)
                                                                       >,
                                                                       sign(<'VA_Cast_Ballot', ~ec,
                                                                             ~new_eid.2,
                                                                             <'VoterAuthorization', ~ec,
                                                                              pseudonym($V.1),
                                                                              pk(~sk_voter.1), ~bs_unused.1,
                                                                              ~ts.3>,
                                                                             sign(<'VoterAuthorization', ~ec,
                                                                                   pseudonym($V.1),
                                                                                   pk(~sk_voter.1),
                                                                                   ~bs_unused.1, ~ts.3>,
                                                                                  '1', ~sk_eas)
                                                                            >,
                                                                            '1', ~sk_voter.1)
                                                                      >
                                                       ) ▶₃ #vr.32 )
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
      qed
    qed
  qed
qed
