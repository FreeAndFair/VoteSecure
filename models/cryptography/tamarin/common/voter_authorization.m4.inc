dnl
dnl The VoterAuthorization data type, shared by the voter authentication,
dnl ballot submission, and ballot cast subprotocols.
dnl
dnl @author Daniel M. Zimmerman
dnl @copyright Free & Fair 2025-26
dnl @version 0.2
dnl
ifdef(<!INCLUDED_VOTER_AUTHORIZATION!>, <!!>, <!
define(<!INCLUDED_VOTER_AUTHORIZATION!>)dnl
macros:
  /*
    Authorization data signed by the EAS and carried by the VA in its
    ballot submission and cast messages; the DBB validates the signature
    in those messages rather than consulting a stored authorization record.
    The nonce ts is fresh for each authorization, ensuring distinct signed
    terms even when all other fields are the same (e.g., when a voter
    re-authenticates before submitting or casting).
   */
  VoterAuthorization(ec_hash, pseudo, pk_voter, ballot_style, ts) = <'VoterAuthorization', ec_hash, pseudo, pk_voter, ballot_style, ts>

!>)dnl
