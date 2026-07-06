dnl
dnl This input file contains Tamarin macros for messages in the trustee
dnl protocols. It uses the default trustee count/thresholds/etc. if none
dnl are already set.
dnl
dnl It is idempotent; if included more than once, every inclusion after the
dnl first will have no effect.
dnl
dnl @author Daniel M. Zimmerman
dnl @copyright Free & Fair 2025
dnl @version 0.1
dnl
include(common/trustee_defaults.m4.inc)
dnl The following tuple is used in messages that contain all the trustee names and public keys.
ifdef(<!TRUSTEE_ID_TUPLE_COMPONENT!>,<!!>,<!define(TRUSTEE_ID_TUPLE_COMPONENT, <!<!<'Trustee$1', id_trustee$1, pk_sign_trustee$1, pk_encrypt_trustee$1>!>!>)!>)dnl
dnl
ifdef(<!TRUSTEE_TAMARIN_MACROS!>, <!!>, <!
  /*
    All message types contain a tag at the beginning, either a single constant
    (like 'Trustee_ID') or a tuple (like <'Trustee_Pairwise_Share', x>). In the
    trustee protocol, each such tag can only appear on the bulletin board _once_
    for each sending trustee; this is enforced via restrictions on the rules that
    post the messages.
   */dnl
ifdef(<!TRUSTEE_SETUP!>, <!
macros:
  Msg_Trustee_ID(name, id, pk_sign, pk_encrypt) = <'Trustee_ID', name, id, pk_sign, pk_encrypt>,
  Msg_TAS_ID(pk_sign) = <'TAS_ID', pk_sign>,
  Msg_TAS_Election_Setup(trustee_tuple, election_definition) = <'TAS_Election_Setup', trustee_tuple, election_definition>,
  Msg_Trustee_Election_Setup_Confirm(id, msg) = <'Trustee_Election_Setup_Confirm', id, msg>,
  Trustee_ID_Tuple() =
    <forloop(<!TN!>, <!1!>, TRUSTEE_COUNT, <!
      TRUSTEE_ID_TUPLE_COMPONENT(TN)ifelse(eval(TN < TRUSTEE_COUNT), eval(1), <!, !>, <!!>)!>)
    >
!>, <!!>)dnl
ifdef(<!ELECTION_KEY_GENERATION!>, <!
macros:
  Msg_Trustee_Check_Value(h_election, check_value) = <'Trustee_Check_Value', h_election, check_value>,
  Msg_Trustee_Pairwise_Share(h_election, recipient, ciphertext) = <<'Trustee_Pairwise_Share', recipient>, h_election, ciphertext>,
  Msg_Trustee_Election_Public_Key(h_election, pk_election) = <'Trustee_Election_Public_Key', h_election, pk_election>
!>, <!!>)dnl
ifdef(<!TRUSTEE_MIXING!>, <!
macros:
  Msg_Trustee_NY_Cryptograms(h_election, sending_trustee, signing_trustee, ballot_order, ballot_set) = <<'Trustee_NY_Cryptograms', sending_trustee, signing_trustee>, h_election, ballot_order, ballot_set>,
  Msg_Trustee_EG_Cryptograms(h_election, mixing_trustee, signing_trustee, ballot_order, ballot_set, shuffle_proof) = <<'Trustee_EG_Cryptograms', mixing_trustee, signing_trustee>, h_election, ballot_order, ballot_set, shuffle_proof>
!>, <!!>)dnl
ifdef(<!TRUSTEE_DECRYPTION!>, <!
macros:
  Msg_TAS_Mixed_Cryptograms(h_election, ballot_set) = <'TAS_Mixed_Cryptograms', h_election, ballot_set>,
  Msg_Trustee_Partial_Decryption(h_election, trustee, partially_decrypted_ballots, partial_decryption_proof) = <'Trustee_Partial_Decryption', h_election, trustee, partially_decrypted_ballots, partial_decryption_proof>,
  Msg_Trustee_Decrypted_Ballots(h_election, trustee, ballots) = <'Trustee_Decrypted_Ballots', h_election, trustee, ballots>
!>, <!!>)dnl
define(TRUSTEE_TAMARIN_MACROS)
!>)dnl
dnl
