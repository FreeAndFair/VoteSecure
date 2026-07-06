simplify
solve( !BB_Root( ~ec, ~bbid, r_unused, root_eid_unused ) ▶₁ #i )
  case BulletinBoard_Create
  solve( !BB_Entry( ~bbid, t,
                    <'BBEntry_Ballot_Submission', ~ec, timestamp,
                     <'VA_Submit_Ballot', ~ec, cryptograms_unused,
                      <'VoterAuthorization', ~ec, pseudo_unused, pk_voter_unused,
                       ballot_style_unused, ts_unused>,
                      sig_auth_unused>,
                     sig_msg_submit_ballot_unused>,
                    prev_unused
         ) ▶₂ #i )
    case BulletinBoard_Append
    solve( BB_Append_Request( ~bbid,
                              <'BBEntry_Ballot_Submission', ~ec, timestamp,
                               <'VA_Submit_Ballot', ~ec, cryptograms_unused,
                                <'VoterAuthorization', ~ec, pseudo_unused, pk_voter_unused,
                                 ballot_style_unused, ts_unused>,
                                sig_auth_unused>,
                               sig_msg_submit_ballot_unused>,
                              prev_unused
           ) ▶₂ #vr.4 )
      case Mock_AppendSubmittedBallot_case_1
      solve( BB_Current( ~bbid, ~root_eid ) ▶₁ #vr.4 )
        case BulletinBoard_Create
        solve( BCA_State_InitiateBallotCheck( ~ec, ~new_eid ) ▶₀ #i )
          case BallotCheck_VA_Check_case_1
          SOLVED // trace found
        qed
      qed
    qed
  qed
qed
