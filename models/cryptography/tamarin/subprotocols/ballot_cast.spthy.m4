dnl
dnl This is the m4 input file for the Ballot Cast Subprotocol.
dnl If the STANDALONE macro is defined, this file generates a standalone
dnl version of the subprotocol; otherwise, it generates a Tamarin code
dnl snippet suitable for inclusion in a Tamarin file composing multiple
dnl subprotocols.
dnl
dnl If the BALLOT_CAST_MOCKS macro is defined (which is always the case
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
  Ballot Cast Subprotocol

  This subprotocol covers ballot casting (the authorization of a voter
  public key and corresponding finalization of a ballot submitted with
  that key such that it is counted in the tally). It uses a secure
  channel abstraction, where adversaries are capable of both intercepting
  and injecting messages into channels, to model secure connections such
  as TLS, but also uses explicit digital signatures for content that needs
  to be posted to the public bulletin board.

  @author Daniel M. Zimmerman
  @copyright Free & Fair 2025
  @version 0.1
 */

theory ballot_cast

begin

define(<!USE_UNIQUE!>)dnl
define(<!USE_EUFCMA_SIGNING!>)dnl
define(<!USE_ABSTRACTED_NAOR_YUNG!>)dnl
define(<!USE_PSEUDONYM!>)dnl
define(<!USE_EQUALITY!>)dnl
define(<!USE_INEQUALITY!>)dnl
include(common/primitives.m4.inc)
define(<!USE_SECURE_CHANNELS!>)dnl
define(<!USE_SECURE_CHANNELS_INJECTION!>)dnl
define(<!USE_SECURE_CHANNELS_INTERCEPTION!>)dnl
include(common/channels.m4.inc)
define(<!USE_NO_BB_ENTRY_WITH_HASH!>)dnl
include(common/bulletinboard.m4.inc)
define(<!USE_SUBMISSION_NOT_ON_BB!>)dnl
define(<!USE_AT_MOST_ONE_CAST_PER_PSEUDONYM!>)dnl
define(<!USE_NO_PREVIOUS_CAST!>)dnl
define(<!USE_MOST_RECENT_BALLOT!>)dnl
include(common/ballot_restrictions.m4.inc)
include(common/trustee_defaults.m4.inc)

!>)dnl
dnl If STANDALONE is defined, all mocks are always required
ifdef(<!STANDALONE!>,<!define(BALLOT_CAST_MOCKS)!>)dnl
dnl
ifdef(<!BALLOT_CAST_MOCKS!>,<!
include(subprotocols/includes/mock_election_setup.m4.inc)
include(subprotocols/includes/mock_voter_auth.m4.inc)
include(subprotocols/includes/mock_ballot_submit.m4.inc)
!>)dnl
dnl
include(common/voter_authorization.m4.inc)
macros:
  /*
    Message types. The ones that include an "ec_hash" will actually use
    the election configuration, not its hash, because it is public
    information and Tamarin doesn't care if we hash it or not.
   */
  Msg_VA_Cast_Ballot(ec_hash, tracker, signed_voter_auth) = <'VA_Cast_Ballot', ec_hash, tracker, signed_voter_auth>,
  Msg_DBB_Cast_Confirmation(ec_hash, sub_tracker, cast_tracker) = <'DBB_Cast_Confirmation', ec_hash, sub_tracker, cast_tracker>,
  Msg_DBB_Cast_Error(ec_hash, error) = <'DBB_Cast_Error', ec_hash, error>,

  /*
    Bulletin board entries. Note that we don't explicitly include the hash
    of the previous bulletin board entry in these, because it is included
    automatically by the bulletin board during the entry append process.
    We also don't include the DBB signature, because we are assuming in
    Tamarin that only the DBB can append messages to the bulletin board
    (that is, only DBB actions create bulletin board entries).
   */
  BBEntry_Ballot_Cast(ec_hash, timestamp, signed_submit_msg, signed_cast_msg) = <'BBEntry_Ballot_Cast', timestamp, signed_submit_msg, signed_cast_msg>
dnl
dnl Include the rules.
dnl

include(subprotocols/includes/ballot_cast_rules.spthy.inc)dnl

dnl
dnl Include the lemmas.
dnl

include(subprotocols/includes/ballot_cast_lemmas.spthy.inc)dnl
ifdef(<!STANDALONE!>,<!
end
!>)dnl
