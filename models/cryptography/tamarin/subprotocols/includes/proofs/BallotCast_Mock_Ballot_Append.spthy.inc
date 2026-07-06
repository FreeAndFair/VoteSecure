simplify
solve( !DBB_Submitted_Ballot( ~ec, ~va_id, ~cid, pseudo, msg ) ▶₀ #i )
  case Mock_Ballot_Submission
  solve( !Mock_Submitted_Ballot( ~ec, ~va_id, $V.1, ~ballot.1, cryptograms,
                                 ~r.1,
                                 <
                                  <'VA_Submit_Ballot', ~ec,
                                   <ny_encrypt_c1(~ballot, pk(~sk_election), ~r),
                                    ny_encrypt_c2(~ballot, pk(~sk_election), ~r),
                                    ny_encrypt_p(~ballot, pk(~sk_election), ~r)>,
                                   <'VoterAuthorization', ~ec, pseudonym($V), pk(~sk_voter), ~ballot_style,
                                    ~ts>,
                                   sign(<'VoterAuthorization', ~ec, pseudonym($V), pk(~sk_voter),
                                         ~ballot_style, ~ts>,
                                        '1', ~sk_eas)
                                  >,
                                  sign(<'VA_Submit_Ballot', ~ec,
                                        <ny_encrypt_c1(~ballot, pk(~sk_election), ~r),
                                         ny_encrypt_c2(~ballot, pk(~sk_election), ~r),
                                         ny_encrypt_p(~ballot, pk(~sk_election), ~r)>,
                                        <'VoterAuthorization', ~ec, pseudonym($V), pk(~sk_voter),
                                         ~ballot_style, ~ts>,
                                        sign(<'VoterAuthorization', ~ec, pseudonym($V), pk(~sk_voter),
                                              ~ballot_style, ~ts>,
                                             '1', ~sk_eas)
                                       >,
                                       '1', ~sk_voter)
                                 >
         ) ▶₁ #i )
    case Mock_Ballot_Submission
    solve( !BB_Root( ~ec, bbid, r_unused, root_eid_unused ) ▶₃ #i )
      case BulletinBoard_Create
      solve( !BB_Entry( ~bbid, prev_eid, e_unused, prev_prev_unused ) ▶₄ #i )
        case BulletinBoard_Append
        solve( BB_Current( ~bbid, prev_prev_unused ) ▶₁ #vr.6 )
          case BulletinBoard_Create
          solve( BB_Append_Request( ~bbid, e_unused, ~root_eid ) ▶₂ #vr.6 )
            case Mock_AppendSubmittedBallot
            SOLVED // trace found
          qed
        qed
      qed
    qed
  qed
qed
