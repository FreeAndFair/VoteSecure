dnl
dnl This is the m4 input file for the Voter Authentication Subprotocol.
dnl If the STANDALONE macro is defined, this file generates a standalone
dnl version of the subprotocol; otherwise, it generates a Tamarin code
dnl snippet suitable for inclusion in a Tamarin file composing multiple
dnl subprotocols.
dnl
dnl If the VOTER_AUTHENTICATION_MOCKS macro is defined (which is always the
dnl case when STANDALONE is defined), the Tamarin code snippet will include
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
  Voter Authentication Subprotocol

  This protocol implements the voter authentication process, which
  involves a third-party KYC provider such as CLEAR (or something with
  a similar API). It involves the voter application, the election
  administration server, the digital ballot box, and the authentication
  server. These communicate using a secure channel abstraction, where
  adversaries are capable of both intercepting and injecting messages
  into channels.

  @author Daniel M. Zimmerman
  @copyright Free & Fair 2025
  @version 0.1
 */

theory voter_authentication

begin

define(<!USE_UNIQUE!>)dnl
define(<!USE_PSEUDONYM!>)dnl
define(<!USE_EUFCMA_SIGNING!>)dnl
include(common/primitives.m4.inc)
define(<!USE_SECURE_CHANNELS!>)dnl
define(<!USE_SECURE_CHANNELS_INJECTION!>)dnl
define(<!USE_SECURE_CHANNELS_INTERCEPTION!>)dnl
include(common/channels.m4.inc)

/*
  We don't include the bulletin board, even though we establish
  a fact for it, because it isn't used in the standalone version.
 */
!>)dnl
dnl If STANDALONE is defined, all mocks are always required
ifdef(<!STANDALONE!>,<!define(VOTER_AUTHENTICATION_MOCKS)!>)dnl
dnl
ifdef(<!VOTER_AUTHENTICATION_MOCKS!>,<!
include(subprotocols/includes/mock_election_setup.m4.inc)
!>)
dnl
include(common/voter_authorization.m4.inc)
macros:
  /*
    Message types. The ones that include an "ec_hash" will actually use
    the election configuration, not its hash, because it is public
    information and Tamarin doesn't care if we hash it or not.
   */
  Msg_EAS_Request_Authentication_Session(project_id, api_key) = <'EAS_Request_Authentication_Session', project_id, api_key>,
  Msg_AS_Authentication_Session(session_id, token) = <'AS_Authentication_Session', session_id, token>,
  Msg_Voter_Authentication(token, voter_id) = <'Voter_Authentication', token, voter_id>,
  Msg_AS_Authentication_Complete(token) = <'AS_Authentication_Complete', token>,
  Msg_EAS_Request_Authentication_Result(session_id) = <'EAS_Request_Authentication_Result', session_id>,
  Msg_AS_Authentication_Result(session_id, voter_id, status) = <'AS_Authentication_Result', session_id, voter_id, status>,
  Msg_VA_Request_Authentication(ec_hash, pk_voter) = <'VA_Request_Authentication', ec_hash, pk_voter>,
  Msg_EAS_Authentication_Session(ec_hash, pk_voter, token) = <'EAS_Authentication_Session', ec_hash, pk_voter, token>,
  Msg_VA_Authentication_Complete(ec_hash, pk_voter, token) = <'VA_Authentication_Complete', ec_hash, pk_voter, token>,
  /* For non-eligible results the voter_auth field is 'ineligible'. */
  Msg_EAS_Authentication_Result(ec_hash, result, pk_voter, voter_auth) = <'EAS_Authentication_Result', result, ec_hash, pk_voter, voter_auth>

include(subprotocols/includes/voter_authentication_rules.spthy.inc)
dnl

include(subprotocols/includes/voter_authentication_lemmas.spthy.inc)
dnl

dnl
ifdef(<!STANDALONE!>,<!
end
!>)dnl
