simplify
solve( VA_State_PresentBallot( ~ec, ~va_id, $V, ~sk_voter ) ▶₀ #i )
  case Mock_Voter_Authentication
  solve( !VA_Eligible_Voter( ~ec, ~va_id, pseudo, ~sk_voter, ~bs,
                             signed_voter_auth
         ) ▶₂ #i )
    case Mock_Voter_Authentication
    solve( !ElectionPublicKey( ~ec, pk_election ) ▶₁ #i )
      case Mock_Finalize_Election_Setup
      SOLVED // trace found
    qed
  qed
qed
