dnl
dnl Tamarin channel rules shared by multiple subprotocols.
dnl
dnl @author Daniel M. Zimmerman
dnl @copyright Free & Fair 2025-26
dnl @version 0.2
dnl
ifdef(<!defined_bool!>, <!!>, <!include(m4_utils/defined_bool.m4)!>)dnl
ifelse(eval(!defined_bool(<!INCLUDED_AUTHENTICATED_CHANNELS!>) && defined_bool(<!USE_AUTHENTICATED_CHANNELS!>)), eval(1), <!
define(<!INCLUDED_AUTHENTICATED_CHANNELS!>)dnl

/*
  An authenticated channel, where messages are guaranteed to be from
  the claimed sender but are not encrypted and can be received by
  multiple arbitrary recipients (including the adversary).

  Usage: Instead of `Out(m)` and `In(m)` facts, use
  `AuthenticatedSend(S, R, m)` and `AuthenticatedReceive(S, R, m)`,
  where `S` is the sender, `R` is the intended receiver, and `m` is
  the message.

  Note: The `!AuthenticMessage` fact should never be used outside these
  two rules.

  Note: No subprotocol currently modeled uses authenticated channels;
  only secure channels (below) are exercised by the current models.
  This definition is retained for reference and possible future use.
  Because it is unexercised, some aspects of its documentation (e.g.,
  message ordering and directionality) are intentionally left less
  detailed than those of the secure channel below.
*/

rule AuthenticatedChannel_Send:
    [ AuthenticatedSend(S, R, m) ]
  --[ AuthenticatedChannel_Out(S, R, m) ]->
    [ !AuthenticatedMessage(S, m), Out(m) ]

rule AuthenticatedChannel_Receive:
    [ !AuthenticatedMessage(S, m), In(R) ]
  --[ AuthenticatedChannel_In(S, R, m) ]->
    [ AuthenticatedReceive(S, R, m) ]
!>, <!!>)dnl
dnl
ifelse(eval(!defined_bool(<!INCLUDED_CONFIDENTIAL_CHANNELS!>) && defined_bool(<!USE_CONFIDENTIAL_CHANNELS!>)), eval(1), <!
define(<!INCLUDED_CONFIDENTIAL_CHANNELS!>)dnl
/*
  A confidential channel, where messages are guaranteed to be received
  only by the claimed recipient, but not to be sent by the claimed
  sender (the adversary can change the claimed sender, but does not get
  access to and cannot change the message contents).

  Usage: Instead of `Out(m)` and `In(m)` facts, use
  `ConfidentialSend(S, R, m)` and `ConfidentialReceive(S, R, m)`,
  where `S` is the sender, `R` is the intended receiver, and `m` is
  the message.

  Note: The `!ConfidentialMessage` fact should never be used outside these
  two rules.

  Note: No subprotocol currently modeled uses confidential channels;
  only secure channels (below) are exercised by the current models.
  This definition is retained for reference and possible future use.
  Because it is unexercised, some aspects of its documentation (e.g.,
  message ordering and directionality) are intentionally left less
  detailed than those of the secure channel below.
*/

rule ConfidentialChannel_Send:
    [ ConfidentialSend(S, R, m) ]
  --[ ConfidentialChannel_Out(S, R, m) ]->
    [ !ConfidentialMessage(R, m) ]

rule ConfidentialChannel_Receive:
    [ !ConfidentialMessage(R, m), In(S) ]
  --[ ConfidentialChannel_In(S, R, m) ]->
    [ ConfidentialReceive(S, R, m) ]
!>, <!!>)dnl
dnl
ifelse(eval(!defined_bool(<!INCLUDED_SECURE_CHANNELS!>) && defined_bool(<!USE_SECURE_CHANNELS!>)), eval(1), <!
define(<!INCLUDED_SECURE_CHANNELS!>)dnl
/*
  A secure channel, where messages are guaranteed to be from the
  claimed sender and to only be received by the claimed recipient
  No other recipient (including the adversary) can learn the message
  contents from the channel without an endpoint reveal. The messages
  are linear facts, so they cannot be replayed and there is no
  guarantee of ordering if multiple messages are in the same channel
  at once.

  Usage: Instead of `Out(m)` and `In(m)` facts, use
  `SecureSend(~cid, S, R, m)` and `SecureReceive(~cid, S, R, m)`,
  where `~cid` is a fresh channel ID when the channel is created,
  `S` is the sender, `R` is the receiver, and `m` is the message.
  Channels are bidirectional (modeling two-way TLS connections),
  but each fresh `~cid` should be used for only one such bidirectional
  connection.

  Note: The `SecureMessage` fact should never be used outside the
  secure channel rules.
 */

rule SecureChannel_Send:
    [ SecureSend(~cid, S, R, m) ]
  --[ SecureChannel_Out(~cid, S, R, m),
      SecureChannel_Message(m) ]->
    [ SecureMessage(~cid, S, R, m) ]

rule SecureChannel_Receive:
    [ SecureMessage(~cid, S, R, m) ]
  --[ SecureChannel_In(~cid, S, R, m) ]->
    [ SecureReceive(~cid, S, R, m) ]
ifdef(<!USE_SECURE_CHANNELS_INJECTION!>, <!
/*
  This rule models a compromised sender on a secure channel,
  where the adversary can inject messages.

  This rule is exercised only by the adversary.  It is adapted from the
  secure-channel injection rule of the 5G-AKA case study in the Tamarin
  manual.  The `In(<~cid, S, R, m>)` premise is the adversary assembling
  a complete secure-channel message (channel id, sender, receiver, and
  payload) from its knowledge and injecting it into the channel; that is
  why it uses a 4-tuple that does not otherwise appear in the premises of
  the rules in this model.
 */
rule SecureChannel_Compromised_Inject:
    [ In(<~cid, S, R, m>) ]
  --[ Reveal(S, 'SecureChannel'),
      SecureChannel_Injected(~cid, S, R, m),
      SecureChannel_InjectedMessage(m) ]->
    [ SecureMessage(~cid, S, R, m) ]
!>, <!!>)dnl
ifdef(<!USE_SECURE_CHANNELS_INTERCEPTION!>, <!
/*
  This rule models the interception of a message on a secure
  channel.
*/
rule SecureChannel_Compromised_Intercept:
    [ SecureMessage(~cid, S, R, m) ]
  --[ Reveal(R, 'SecureChannel'),
      SecureChannel_Intercepted(~cid, S, R, m),
      SecureChannel_InterceptedMessage(m) ]->
    [ Out(~cid),
      Out(S),
      Out(R),
      Out(m) ]
!>, <!!>)!>, <!!>)dnl
