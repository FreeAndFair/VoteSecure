/* Voter Authentication Subprotocol Rules */

/* Authentication Server (AS) */

/*
  This rule creates the project ID and API key for the EAS to use
  with the AS. It is assumed that these are shared out of band. Note that
  as far as Tamarin is concerned, it doesn't matter that these are two
  different secrets, and we could just as easily model them as a single
  secret (`project_id_and_api_key`).
 */
rule VoterAuthentication_AS_Initialize [role="AS"]:
    [ Fr(~project_id),
      Fr(~api_key) ]
  --[ AS_Secrets_Trace(~project_id, ~api_key),
      Unique('AS_Initialize') ]->
    [ !AS_Secrets(~project_id, ~api_key) ]

/*
  This rule starts an authentication process on the AS by creating
  the session ID and authentication token and returning them to the EAS.
  It receives the request from the EAS on a secure channel, modeling
  the TLS-based communication with an external authentication API,
  and responds on the same channel.
 */
rule VoterAuthentication_AS_AuthenticationRequest [role="AS"]:
  let msg_request_auth_session = Msg_EAS_Request_Authentication_Session(~project_id, ~api_key)
      msg_auth_session = Msg_AS_Authentication_Session(~session_id, ~token) in
    [ !AS_Secrets(~project_id, ~api_key),
      SecureReceive(~cid, requesting_eas, 'AS', msg_request_auth_session),
      Fr(~session_id),
      Fr(~token) ]
  --[ AS_AuthenticationRequest_Trace(~session_id, ~token),
      IN_SECURE_RECEIVE(~cid, requesting_eas, 'AS', msg_request_auth_session) ]->
    [ !AS_AuthenticationRequested(~session_id, ~token),
      SecureSend(~cid, 'AS', requesting_eas, msg_auth_session),
      AS_State_AwaitAuthentication(~session_id, ~token) ]

/*
  This rule simulates a successful authentication process by a voter. It
  receives the authentication data from the voter on a secure channel,
  and responds on the same channel, modeling the TLS-based communication with
  the voter's browser/app. The authentication data is abstracted into a
  single "identity" that is claimed by the voter, and stored in a persistent
  fact associated with the authentication session.

  Note that for a given authentication session, either this rule or the
  unsuccessful authentication rule, but not both, can be executed (this will
  be verified with a safety lemma).
 */
rule VoterAuthentication_AS_SuccessfulAuthentication [role="AS"]:
  let msg_voter_auth = Msg_Voter_Authentication(~token, $voter_id)
      msg_auth_complete = Msg_AS_Authentication_Complete(~token) in
    [ AS_State_AwaitAuthentication(~session_id, ~token),
      SecureReceive(~cid, ~v_id, 'AS', msg_voter_auth) ]
  --[ AS_SuccessfulAuthentication_Trace(~session_id) ]->
    [ !AS_Authentication_Status(~session_id, $voter_id, 'successful'),
      SecureSend(~cid, 'AS', ~v_id, msg_auth_complete) ]

/*
  This rule simulates an unsuccessful authentication process by a voter. It
  receives the authentication data from the voter on a secure channel,
  and responds on the same channel, modeling the TLS-based communication with
  the voter's browser/app. The authentication data is abstracted into a
  single "identity" that is claimed by the voter, and stored in a persistent
  fact associated with the authentication session.

  Note that for a given authentication session, either this rule or the
  successful authentication rule, but not both, can be executed (this will
  be verified with a safety lemma).
 */
rule VoterAuthentication_AS_UnsuccessfulAuthentication [role="AS"]:
  let msg_voter_auth = Msg_Voter_Authentication(~token, $voter_id)
      msg_auth_complete = Msg_AS_Authentication_Complete(~token) in
    [ AS_State_AwaitAuthentication(~session_id, ~token),
      SecureReceive(~cid, ~v_id, 'AS', msg_voter_auth) ]
  --[ AS_UnsuccessfulAuthentication_Trace(~session_id) ]->
    [ !AS_Authentication_Status(~session_id, $voter_id, 'unsuccessful'),
      SecureSend(~cid, 'AS', ~v_id, msg_auth_complete) ]

/*
  This rule sends the authentication result for a particular `session_id` to the
  EAS upon request, responding via the same secure channel that was used
  for the request.
 */
rule VoterAuthentication_AS_ReportAuthenticationResult [role="AS"]:
  let msg_req_auth_result = Msg_EAS_Request_Authentication_Result(~session_id)
      msg_auth_result = Msg_AS_Authentication_Result(~session_id, $voter_id, status) in
    [ !AS_Authentication_Status(~session_id, $voter_id, status),
      SecureReceive(~cid, requesting_eas, 'AS', msg_req_auth_result) ]
  --[ AS_ReportAuthenticationResult_Trace(~session_id, status),
      AS_Complete_Authentication(~session_id),
      IN_SECURE_RECEIVE(~cid, requesting_eas, 'AS', msg_req_auth_result) ]->
    [ SecureSend(~cid, 'AS', requesting_eas, msg_auth_result) ]

/*
  This restriction controls the above rule, and states that action
  `AS_Complete_Authentication` can only exist in the trace if there is
  an earlier successful or unsuccessful authentication action in the
  trace for the same session ID. Note that _later_ such actions can
  exist, reflecting the fact that authentication might be completed
  after the EAS requests the result in the case where an adversary
  controls the channel between a VA and the EAS.
 */
restriction AS_Complete_Authentication:
  "
    All session_id #i.
          AS_Complete_Authentication(session_id)@i
      ==>
            (Ex #j. AS_SuccessfulAuthentication_Trace(session_id)@j & #j < #i)
          |
            (Ex #j. AS_UnsuccessfulAuthentication_Trace(session_id)@j & #j < #i)
  "

/*
  This rule sends the authentication result for a particular `session_id` that
  has not been completed to the EAS upon request, responding via the same
  secure channel that was used for the request. It can only fire if there is
  no authentication status in the trace already.
 */
rule VoterAuthentication_AS_ReportIncompleteAuthenticationResult [role="AS"]:
  let msg_req_auth_result = Msg_EAS_Request_Authentication_Result(~session_id)
      msg_auth_result = Msg_AS_Authentication_Result(~session_id, 'unknown', 'incomplete') in
    [ !AS_AuthenticationRequested(~session_id, ~token),
      SecureReceive(~cid, requesting_eas, 'AS', msg_req_auth_result) ]
  --[ AS_ReportIncompleteAuthenticationResult_Trace(~session_id),
      AS_Incomplete_Authentication(~session_id),
      IN_SECURE_RECEIVE(~cid, requesting_eas, 'AS', msg_req_auth_result) ]->
    [ SecureSend(~cid, 'AS', requesting_eas, msg_auth_result) ]

/*
  This restriction controls the above rule, and states that action
  `AS_Incomplete_Authentication` can only exist in the trace if there is
  no earlier successful or unsuccessful authentication action in the
  trace for the same session ID. Note that _later_ such actions can
  exist, reflecting the fact that authentication might be completed
  after the EAS requests the result in the case where an adversary
  controls the channel between a VA and the EAS.
 */
restriction AS_Incomplete_Authentication:
  "
    All session_id #i.
          AS_Incomplete_Authentication(session_id)@i
      ==>
            not (Ex #j. AS_SuccessfulAuthentication_Trace(session_id)@j & #j < #i)
          &
            not (Ex #j. AS_UnsuccessfulAuthentication_Trace(session_id)@j & #j < #i)
  "

/* Election Administration Server (EAS) */

/*
  This rule receives an authentication request from a voting application (VA)
  and requests an authentication session from the AS. We model the request
  using a secure channel, because we expect a TLS connection between the VA
  and the EAS, and we will respond on the same channel after getting the
  session information from the AS.
 */
rule VoterAuthentication_EAS_RequestAuthentication [role="EAS"]:
  let msg_req_auth = Msg_VA_Request_Authentication(~ec, pk_voter)
      msg_req_auth_session = Msg_EAS_Request_Authentication_Session(~project_id, ~api_key) in
    [ !ElectionConfiguration(~ec),
      !AS_Secrets(~project_id, ~api_key),
      SecureReceive(~cid_va, ~va_id, <~ec, 'EAS'>, msg_req_auth),
      Fr(~cid_as) ]
  --[ EAS_RequestAuthentication_Trace(~va_id, pk_voter),
      IN_SECURE_RECEIVE(~cid_va, ~va_id, <~ec, 'EAS'>, msg_req_auth) ]->
    [ SecureSend(~cid_as, <~ec, 'EAS'>, 'AS', msg_req_auth_session),
      EAS_State_ReceiveAuthenticationSession(~ec, ~cid_as, ~cid_va, ~va_id, pk_voter) ]

/*
  This rule receives session information from the AS for a requested
  authentication session and sends the session token to the requesting VA.
 */
rule VoterAuthentication_EAS_ReceiveAuthenticationSession [role="EAS"]:
  let msg_auth_session_in = Msg_AS_Authentication_Session(~session_id, ~token)
      msg_auth_session_out = Msg_EAS_Authentication_Session(~ec, pk_voter, ~token) in
    [ EAS_State_ReceiveAuthenticationSession(~ec, ~cid_as, ~cid_va, ~va_id, pk_voter),
      SecureReceive(~cid_as, 'AS', <~ec, 'EAS'>, msg_auth_session_in) ]
  --[ EAS_ReceiveAuthenticationSession_Trace(~va_id, pk_voter, ~session_id, ~token) ]->
    [ SecureSend(~cid_va, <~ec, 'EAS'>, ~va_id, msg_auth_session_out),
      EAS_State_ReceiveAuthenticationComplete(~ec, ~va_id, pk_voter, ~session_id, ~token) ]

/*
  This rule receives the authentication complete message from a VA and
  requests the authentication result from the AS.
 */
rule VoterAuthentication_EAS_ReceiveAuthenticationComplete [role="EAS"]:
  let msg_auth_complete = Msg_VA_Authentication_Complete(~ec, pk_voter, ~token)
      msg_req_auth_result = Msg_EAS_Request_Authentication_Result(~session_id) in
    [ EAS_State_ReceiveAuthenticationComplete(~ec, ~va_id, pk_voter, ~session_id, ~token),
      SecureReceive(~cid_va, ~va_id, <~ec, 'EAS'>, msg_auth_complete),
      Fr(~cid_as) ]
  --[ EAS_ReceiveAuthenticationComplete_Trace(~va_id, pk_voter, ~session_id, ~token),
      IN_SECURE_RECEIVE(~cid_va, ~va_id, <~ec, 'EAS'>, msg_auth_complete) ]->
    [ SecureSend(~cid_as, <~ec, 'EAS'>, 'AS', msg_req_auth_result),
      EAS_State_ReceiveAuthenticationResult(~ec, ~cid_as, ~cid_va, ~va_id, pk_voter, ~session_id, ~token) ]

/* TODO: perhaps model revocation of voter eligibility during the election? */
/* TODO: perhaps model the EAS knowing whether a voter has cast a ballot? */

/*
  This rule receives the authentication result message from the AS for a
  successful authentication of an eligible voter, sends the appropriate
  information to the VA that reported authentication completion, and tells
  the DBB that the voter key is eligible to vote its ballot style.
 */
rule VoterAuthentication_EAS_ReceiveAuthenticationResult_Successful_Eligible [role="EAS"]:
  let msg_auth_result_in = Msg_AS_Authentication_Result(~session_id, $voter_id, 'successful')
      auth_data = VoterAuthorization(~ec, pseudonym($voter_id), pk_voter, ballot_style, ~ts)
      signed_voter_auth = <auth_data, sign(auth_data, '1', ~sk_eas)>
      msg_auth_result_out = Msg_EAS_Authentication_Result(~ec, 'eligible', pk_voter, signed_voter_auth) in
    [ EAS_State_ReceiveAuthenticationResult(~ec, ~cid_as, ~cid_va, ~va_id, pk_voter, ~session_id, ~token),
      !EASSecretKey(~ec, ~sk_eas),
      !EligibleVoter(~ec, $voter_id, ballot_style),
      SecureReceive(~cid_as, 'AS', <~ec, 'EAS'>, msg_auth_result_in),
      Fr(~ts) ]
  --[ EAS_ReceiveAuthenticationResult_Trace(~session_id, $voter_id, pseudonym($voter_id), ballot_style) ]->
    [ SecureSend(~cid_va, <~ec, 'EAS'>, ~va_id, msg_auth_result_out) ]

/*
  This rule receives the authentication result message from the AS for a
  successful authentication of a non-eligible voter and sends the appropriate
  information to the VA that reported authentication completion. Since we
  can't check for the absence of a persistent fact about the voter's
  eligibility, we use a restriction to ensure that the voter is ineligible.
 */
rule VoterAuthentication_EAS_ReceiveAuthenticationResult_Successful_Ineligible [role="EAS"]:
  let msg_auth_result_in = Msg_AS_Authentication_Result(~session_id, $voter_id, 'successful')
      msg_auth_result_out = Msg_EAS_Authentication_Result(~ec, 'ineligible', pk_voter, 'ineligible') in
    [ EAS_State_ReceiveAuthenticationResult(~ec, ~cid_as, ~cid_va, ~va_id, pk_voter, ~session_id, ~token),
      SecureReceive(~cid_as, 'AS', <~ec, 'EAS'>, msg_auth_result_in) ]
  --[ EAS_ReceiveAuthenticationResult_Trace(~session_id, $voter_id, 'ineligible', 'ineligible'),
      EAS_Ineligible_Voter($voter_id) ]->
    [ SecureSend(~cid_va, <~ec, 'EAS'>, ~va_id, msg_auth_result_out) ]

/*
  This restriction controls the above rule, and states that action
  `EAS_Ineligible_Voter` can only exist in the trace if there is no
  `EligibleVoter_Trace` action for that voter in the trace.
 */
restriction EAS_Ineligible_Voter:
  "
    All voter_id #i.
          EAS_Ineligible_Voter(voter_id)@i
      ==>
          /* Note: this might change depending on whether we invalidate voter
             eligibility during elections. */
          not (Ex ec ballot_style #j.
                  EligibleVoter_Trace(ec, voter_id, ballot_style)@j)
  "

/*
  This rule receives the authentication result from the AS for an
  unsuccessful authentication and sends the appropriate information
  to the VA that reported authentication completion.
 */
rule VoterAuthentication_EAS_ReceiveAuthenticationResult_Unsuccessful [role="EAS"]:
  let msg_auth_result_in = Msg_AS_Authentication_Result(~session_id, $voter_id, 'unsuccessful')
      msg_auth_result_out = Msg_EAS_Authentication_Result(~ec, 'unsuccessful', pk_voter, 'ineligible') in
    [ EAS_State_ReceiveAuthenticationResult(~ec, ~cid_as, ~cid_va, ~va_id, pk_voter, ~session_id, ~token),
      SecureReceive(~cid_as, 'AS', <~ec, 'EAS'>, msg_auth_result_in) ]
  --[ EAS_ReceiveAuthenticationResult_Trace(~session_id, 'unsuccessful', 'ineligible', 'ineligible') ]->
    [ SecureSend(~cid_va, <~ec, 'EAS'>, ~va_id, msg_auth_result_out) ]

/*
  This rule receives the authentication result from the AS for an
  incomplete authentication. This indicates a protocol error (e.g., a
  compromised VA or AS), because it should never have asked for that
  information from the AS unless the authentication was, in fact,
  complete.
 */
rule VoterAuthentication_EAS_ReceiveAuthenticationResult_Incomplete [role="EAS"]:
  let msg_auth_result = Msg_AS_Authentication_Result(~session_id, $voter_id, 'incomplete') in
    [ EAS_State_ReceiveAuthenticationResult(~ec, ~cid_as, ~cid_va, ~va_id, pk_voter, ~session_id, ~token),
      SecureReceive(~cid_as, 'AS', <~ec, 'EAS'>, msg_auth_result) ]
  --[ EAS_ReceiveAuthenticationResult_Trace(~session_id, 'incomplete', 'ineligible', 'ineligible'),
      EAS_Possible_Compromise_Detected_Trace(~va_id),
      EAS_Possible_Compromise_Detected_Trace('AS') ]->
    [ !EAS_Possible_Compromise_Detected(~va_id),
      !EAS_Possible_Compromise_Detected('AS') ]

/*
  Voting Application (VA) and Voter Browser/User Agent

  Note that we don't model these separately here, because the communication
  between them is essentially "the voter clicks and is put into a browser
  view for authentication", which means that in Tamarin they might as well
  be the same actor.
*/

/*
  This rule starts a new voting application for a given election, creates
  a voter key pair, and requests to start the voter authentication process.
  Note the arbitrary public name for a voter in the next state fact; this
  is the name that will be used for authentication later.
 */
rule VoterAuthentication_VA_Initialize [role="VA"]:
  let pk_voter = pk(~sk_voter)
      msg_request_authentication = Msg_VA_Request_Authentication(~ec, pk_voter) in
    [ !ElectionConfiguration(~ec),
      Fr(~va_id),
      Fr(~sk_voter),
      Fr(~cid) ]
  --[ VA_Initialize_Trace(~ec, ~va_id, pk_voter, $V),
      HonestSignatureKey(pk(~sk_voter)) ]->
    [ SecureSend(~cid, ~va_id, <~ec, 'EAS'>, msg_request_authentication),
      VA_State_ReceiveAuthenticationSession(~ec, ~va_id, $V, ~sk_voter, ~cid) ]

/*
  This rule waits for a message providing an authentication session and
  initiates the authentication; note that we do not model the voter's
  user-agent separately here. Authentication is attempted for an
  arbitrary public identifier, which may or may not be an actual
  registered voter.
 */
rule VoterAuthentication_VA_ReceiveAuthenticationSession [role="VA"]:
  let pk_voter = pk(~sk_voter)
      msg_session = Msg_EAS_Authentication_Session(~ec, pk_voter, ~token)
      msg_voter_auth = Msg_Voter_Authentication(~token, $V) in
    [ VA_State_ReceiveAuthenticationSession(~ec, ~va_id, $V, ~sk_voter, ~cid_eas),
      Fr(~cid_as),
      SecureReceive(~cid_eas, <~ec, 'EAS'>, ~va_id, msg_session) ]
  --[ VA_ReceiveAuthenticationSession_Trace(~ec, ~va_id, ~token) ]->
    [ SecureSend(~cid_as, ~va_id, 'AS', msg_voter_auth),
      VA_State_ReceiveAuthenticationComplete(~ec, ~va_id, $V, ~sk_voter, ~cid_as, ~token) ]

/*
  This rule waits for the AS to notify the VA that the authentication
  process is complete, and notifies the EAS when that happens.
 */
rule VoterAuthentication_VA_ReceiveAuthenticationComplete [role="VA"]:
  let pk_voter = pk(~sk_voter)
      msg_as_auth_complete = Msg_AS_Authentication_Complete(~token)
      msg_va_auth_complete = Msg_VA_Authentication_Complete(~ec, pk_voter, ~token) in
    [ VA_State_ReceiveAuthenticationComplete(~ec, ~va_id, $V, ~sk_voter, ~cid_as, ~token),
      Fr(~cid_eas),
      SecureReceive(~cid_as, 'AS', ~va_id, msg_as_auth_complete) ]
  --[ VA_ReceiveAuthenticationComplete_Trace(~ec, ~va_id, ~token) ]->
    [ SecureSend(~cid_eas, ~va_id, <~ec, 'EAS'>, msg_va_auth_complete),
      VA_State_ReceiveAuthenticationResult(~ec, ~va_id, $V, ~sk_voter, ~cid_eas, ~token) ]

/*
  This rule waits for a successful authentication result from the EAS,
  establishes the state that allows the voter to cast a vote with a
  particular ballot style, and links the voter pseudonym to its private key.
 */
rule VoterAuthentication_VA_ReceiveAuthenticationResult_Eligible [role="VA"]:
  let pk_voter = pk(~sk_voter)
      auth_data = VoterAuthorization(~ec, pseudo, pk_voter, ballot_style, ts)
      signed_voter_auth = <auth_data, sig_auth>
      msg_auth_result = Msg_EAS_Authentication_Result(~ec, 'eligible', pk_voter, signed_voter_auth) in
    [ VA_State_ReceiveAuthenticationResult(~ec, ~va_id, $V, ~sk_voter, ~cid, ~token),
      SecureReceive(~cid, <~ec, 'EAS'>, ~va_id, msg_auth_result) ]
  --[ VA_ReceiveAuthenticationResult_Trace(~ec, ~va_id, 'eligible', pseudo, pk_voter, ballot_style),
      IN_SECURE_RECEIVE(~cid, <~ec, 'EAS'>, ~va_id, msg_auth_result) ]->
    [ !VA_Eligible_Voter(~ec, ~va_id, pseudo, ~sk_voter, ballot_style, signed_voter_auth),
      VA_State_PresentBallot(~ec, ~va_id, $V, ~sk_voter) ]

/*
  This rule waits for a successful-but-ineligible authentication result
  from the EAS, records it in the trace, and ends the session. From a
  protocol perspective, this is basically the same as an unsuccessful
  authentication.
 */
rule VoterAuthentication_VA_ReceiveAuthenticationResult_Ineligible [role="VA"]:
  let pk_voter = pk(~sk_voter)
      msg_auth_result = Msg_EAS_Authentication_Result(~ec, 'ineligible', pk_voter, 'ineligible') in
    [ VA_State_ReceiveAuthenticationResult(~ec, ~va_id, $V, ~sk_voter, ~cid, ~token),
      SecureReceive(~cid, <~ec, 'EAS'>, ~va_id, msg_auth_result) ]
  --[ VA_ReceiveAuthenticationResult_Trace(~ec, ~va_id, 'ineligible', 'ineligible', pk_voter, 'ineligible') ]->
    [ VA_State_PresentIneligibilityInformation(~ec, ~va_id, $V, ~sk_voter) /* this fact leads nowhere */ ]

/*
  This rule waits for an unsuccessful authentication result from the EAS,
  records it in the trace, and ends the session. From a protocol perspective,
  this is basically the same as a successful-but-ineligible authentication.
 */
rule VoterAuthentication_VA_ReceiveAuthenticationResult_Unsuccessful [role="VA"]:
  let pk_voter = pk(~sk_voter)
      msg_auth_result = Msg_EAS_Authentication_Result(~ec, 'unsuccessful', pk_voter, 'ineligible') in
    [ VA_State_ReceiveAuthenticationResult(~ec, ~va_id, $V, ~sk_voter, ~cid, ~token),
      SecureReceive(~cid, <~ec, 'EAS'>, ~va_id, msg_auth_result) ]
  --[ VA_ReceiveAuthenticationResult_Trace(~ec, ~va_id, 'unsuccessful', 'ineligible', pk_voter, 'ineligible') ]->
    [ VA_State_PresentUnsuccessfulAuthentication(~ec, ~va_id, $V, ~sk_voter) /* this fact leads nowhere */ ]
