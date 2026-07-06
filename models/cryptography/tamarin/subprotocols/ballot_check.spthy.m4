dnl
dnl This is the m4 input file for the Ballot Check Subprotocol.
dnl If the STANDALONE macro is defined, this file generates a standalone
dnl version of the subprotocol; otherwise, it generates a Tamarin code
dnl snippet suitable for inclusion in a Tamarin file composing multiple
dnl subprotocols.
dnl
dnl If the BALLOT_CHECK_MOCKS macro is defined (which is always the case
dnl when STANDALONE is defined), the Tamarin code snippet will include
dnl mock rules that simulate required actions of other subprotocols by
dnl establishing suitable linear/persistent/action facts.
dnl
dnl @author Daniel M. Zimmerman
dnl @copyright Free & Fair 2025-26
dnl @version 0.2
dnl
dnl We change the m4 quote characters to <! and !>, so that they don't
dnl interfere with Tamarin's quote characters or any comments we might
dnl want to write. The incantation below makes that change, and ensures
dnl that we don't try to change them if we've already done so (e.g.,
dnl when including this file in a composition).
dnl
ifdef(<!QUOTE_CHANGED!>,<!!>,<!changequote(`<!', `!>')!>)dnl
dnl
ifdef(<!STANDALONE!>,<!/*
  Ballot Check Subprotocol

  This subprotocol covers ballot checking (a voter using a second
  application to ensure that the ballot on the bulletin board
  actually contains the ballot choices the voter expects it to). It
  uses a secure channel abstraction, wehre adversaries are capable of
  both intercepting and injecting messages into channels, to model
  secure connections such as TLS, but also uses explicit digital
  signatures for content that needs to be posted to the public
  bulletin board.

  @author Daniel M. Zimmerman
  @copyright Free & Fair 2025
  @version 0.1
 */

theory ballot_check

begin

define(<!USE_UNIQUE!>)dnl
define(<!USE_EUFCMA_SIGNING!>)dnl
define(<!USE_ABSTRACTED_NAOR_YUNG!>)dnl
define(<!USE_PSEUDONYM!>)dnl
define(<!USE_EQUALITY!>)dnl
include(common/primitives.m4.inc)
define(<!USE_SECURE_CHANNELS!>)dnl
define(<!USE_SECURE_CHANNELS_INJECTION!>)dnl
define(<!USE_SECURE_CHANNELS_INTERCEPTION!>)dnl
include(common/channels.m4.inc)
include(common/bulletinboard.m4.inc)

!>)dnl
dnl If STANDALONE is defined, all mocks are always required
ifdef(<!STANDALONE!>,<!define(BALLOT_CHECK_MOCKS)!>)dnl
dnl
ifdef(<!BALLOT_CHECK_MOCKS!>,<!
include(subprotocols/includes/mock_election_setup.m4.inc)
include(subprotocols/includes/mock_voter_auth.m4.inc)
include(subprotocols/includes/mock_ballot_submit.m4.inc)
!>)dnl
dnl
macros:
  /*
    Message types. The ones that include an "ec_hash" will actually use
    the election configuration, not its hash, because it is public
    information and Tamarin doesn't care if we hash it or not.
   */
  Msg_BCA_Check_Request(ec_hash, tracker, pk_encrypt, pk_sign) = <'BCA_Check_Request', ec_hash, tracker, pk_encrypt, pk_sign>,
  Msg_DBB_Check_Request(ec_hash, signed_bca_check_request) = <'DBB_Check_Request', signed_bca_check_request>,
  Msg_VA_Check_Randomizers(ec_hash, signed_bca_check_request, randomizers, pk_voter) = <'VA_Check_Randomizers', signed_bca_check_request, randomizers, pk_voter>,
  Msg_DBB_Check_Randomizers(ec_hash, signed_va_randomizers) = <'DBB_Check_Randomizers', ec_hash, signed_va_randomizers>
dnl
dnl Include the rules.
dnl

include(subprotocols/includes/ballot_check_rules.spthy.inc)dnl

dnl
dnl Include the lemmas.
dnl

include(subprotocols/includes/ballot_check_lemmas.spthy.inc)dnl
ifdef(<!STANDALONE!>,<!
end
!>)dnl
