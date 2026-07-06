dnl
dnl This is the m4 input file for the Ballot Submission Subprotocol.
dnl If the STANDALONE macro is defined, this file generates a standalone
dnl version of the subprotocol; otherwise, it generates a Tamarin code
dnl snippet suitable for inclusion in a Tamarin file composing multiple
dnl subprotocols.
dnl
dnl If the BALLOT_SUBMISSION_MOCKS macro is defined (which is always the case
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
  Ballot Submission Subprotocol

  This subprotocol covers ballot submission (the posting of a
  ballot to the bulletin board before it is either cast or checked).
  It uses a secure channel abstraction, where adversaries are capable
  of both intercepting and injecting messages into channels, to model
  secure connections such as TLS, but also uses explicit digital
  signatures for content that needs to be posted to the public
  bulletin board.

  @author Daniel M. Zimmerman
  @copyright Free & Fair 2025
  @version 0.1
 */

theory ballot_submission

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
include(common/ballot_restrictions.m4.inc)
include(common/trustee_defaults.m4.inc)

!>)dnl
dnl If STANDALONE is defined, all mocks are always required
ifdef(<!STANDALONE!>,<!define(BALLOT_SUBMISSION_MOCKS)!>)dnl
dnl
ifdef(<!BALLOT_SUBMISSION_MOCKS!>,<!
include(subprotocols/includes/mock_election_setup.m4.inc)
include(subprotocols/includes/mock_voter_auth.m4.inc)
!>)
dnl
include(common/voter_authorization.m4.inc)
macros:
  /*
    Message types. The ones that include an "ec_hash" will actually use
    the election configuration, not its hash, because it is public
    information and Tamarin doesn't care if we hash it or not. The ones
    that include "cryptograms" will actually only include a single
    cryptogram (with two ciphertext components and a proof), because we
    don't really care at this level about specific contests, and going
    from one cryptogram to a list is easily generalizable.
   */
  Msg_VA_Submit_Ballot(ec_hash, cryptograms, signed_voter_auth) = <'VA_Submit_Ballot', ec_hash, cryptograms, signed_voter_auth>,
  Msg_DBB_Ballot_Tracker(ec_hash, tracker) = <'DBB_Ballot_Tracker', ec_hash, tracker>,
  Msg_DBB_Ballot_Error(ec_hash, error) = <'DBB_Ballot_Error', ec_hash, error>,

  /*
    Bulletin board entries. Note that we don't explicitly include the hash
    of the previous bulletin board entry in these, because it is included
    automatically by the bulletin board during the entry append process.
    We also don't include the DBB signature, because we are assuming in
    Tamarin that only the DBB can append messages to the bulletin board
    (that is, only DBB actions create bulletin board entries).
   */
  BBEntry_Ballot_Submission(ec_hash, timestamp, ballot_msg) = <'BBEntry_Ballot_Submission', ec_hash, timestamp, ballot_msg>
dnl
dnl Include the rules.
dnl

include(subprotocols/includes/ballot_submission_rules.spthy.inc)dnl

dnl
dnl Include the lemmas.
dnl

include(subprotocols/includes/ballot_submission_lemmas.spthy.inc)dnl

dnl
ifdef(<!STANDALONE!>,<!
end
!>)dnl
