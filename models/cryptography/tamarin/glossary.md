# Glossary

This file summarizes the Tamarin constructs (restriction actions, roles, state facts) that are used across the various subprotocols within the VoteSecure model.

## Restriction Actions

We use many restrictions to control the execution of Tamarin's rules in various ways. The following are brief descriptions of their semantics. Note that we only describe here some of the restrictions that are actually "invoked" as actions in Tamarin rules. Those that are only used locally (and are defined in close proximity to where they are used), and those that stand alone (e.g., some of the restrictions on digital signatures), are not listed here but are documented with their respective definitions.

### Signature Restriction Actions

The strategy we use for modeling signatures is described in in Chapter 15 of the Tamarin book. Here, we describe only the parts that are visible as restriction actions.

- `HonestSignatureKey(key)` denotes that a particular secret signing key was generated honestly.
- `SignatureVerified(sig, sigm, sigpk, verm, verpk, res)` denotes that the verification of signature `sig`, which was _actually_ generated from message `sigm` using the secret key corresponding to public `sigpk`, against message `verm` and public key `verpk`, has result `res` (which can be `true` or `false`). Thus, to indicate that a rule executes only when a signature verifies correctly, one uses the restriction `SignatureVerified(sig, sigm, sigpk, verm, verpk, true)` with appropriate values for the parameters, and similarly (with `false`) to indicate that a rule executes only when a signature fails to verify.

### General Rule Execution Control Actions

- `Eq(x, y)` restricts a rule to only execute if `x` and `y` are equivalent.
- `Neq(x, y)` restricts a rule to only execute if `x` and `y` are not equivalent.
- `OnlyOnce()` can only appear once in the entire trace, so any rule that has it as an action can only execute once, and if multiple rules have it as an action, only one of them can ever execute.
- `Unique(x)` can only appear once in the entire trace for each `x`, and is used to restrict rules to running at most once; for example, we use it to ensure that each trustee only performs its shuffle at most once.

### Bulletin Board-Related Control Actions

- `NoPreviousCast(pseudo)` restricts a rule to run only if the specified pseudonym has not cast a ballot (in any election; if we wanted to model multiple simultaneous elections in which the same real voter could vote, we would need to make a subtle change to `pseudonym` in the equational theory).
- `MostRecentBallot(bbid, pseudo, %idx)` restricts a rule to run only when the entry at index `%idx` on the bulletin board with ID `bbid` is the most recent ballot submitted by the voter with pseudonym `pseudo`.
- `Unauthorized(ec, pseudo, pk)` restricts a rule to run only when a specific public key `pk` is _not_ authorized to vote on behalf of the voter with pseudonym `pseudo` in the election with configuration `ec`.
- `MostRecentAuthorization(ec, pseudo, pk, %idx)` restricts a rule to run only when `pk` is the most recently authorized public key for the voter with pseudonym `pseudo` in the election with configuration `ec`; `%idx` is the index of the authorization, which is used to determine whether it is the latest one.
- `SubmissionNotOnBB(bbid, msg)` restricts a rule to run only if `msg` is _not_ a ballot submission that was posted to the bulletin board with ID `bbid` at some point in the past.
- `AuthorizationNotOnBB(bbid, msg)` restricts a rule to run only if `msg` is _not_ a voter authorization that was posted to the bulletin board with ID `bbid` at some point in the past.
- `CastNotOnBB(bbid, msg1, msg2)` restricts a rule to run only if `msg1` and `msg2` are _not_ a voter ballot cast (`msg1` being the ballot submission, `msg2` being the ballot cast) that was posted to the bulletin board with ID `bbid` at some point in the past.
- `NoBBEntryWithHash(bbid, hash)` restricts a rule to run only if there is no entry on the bulletin board with ID `bbid` that has hash `hash`.

## Roles

- **AS**: The authentication service; in these models; it "randomly" approves or disapproves authentication requests given specific information, so as to be able to test both eventualities.
- **BCA**: A ballot check application.
- **DBB**: The digital ballot box; it is the only role that can post to the public bulletin board, and it keeps track of the most recently authenticated public key for each pseudonym and mediates the ballot check protocol.
- **EAS**: The election administration server; in these models, it handles authentication session requests, voter eligibility, and pseudonyms.
- **Mock**: The role assigned to any rule that implements a mock of some part of the protocol; for example, the rule that creates authenticated voters as part of the standalone ballot submission protocol.
- **TAS**: The trustee administration server. This role primarily serves to store the canonical version of the trustee board in the trustee protocols, but also performs setup tasks such as creating an initial message with the set of ballots for the trustee board.
- **Trustee**: A trustee.
- **VA**: The voting application.

## State Facts

We include here (at least for now) only those persistent state facts that are shared across subprotocols, and not the linear "state machine state" facts that end one subprotocol and start another. Note that some or all of these state facts must be "mocked" when examining subprotocols in isolation (for example, when examining the ballot submission subprotocol without the authentication subprotocol, the voting application in the former must still get a key pair for the voter from somewhere).

Note that we do not indicate the Tamarin "fresh" sort (~) in these state facts, as they are sometimes used with fresh values and sometimes used without. In some cases, we change the names of state fact parameters here from their use in the actual Tamarin theories, for clarity in isolation.

### Election Setup

- `!ElectionConfiguation(ec)` indicates that `ec` is a valid election configuration; in the model, the election configuration contains no information, it is just created as a fresh Tamarin value.
- `!ElectionPublicKey(ec, key)` indicates that `key` is the election public key for the election with configuration `ec`.
- `!ElectionSecretKey(ec, key)` indicates that `key` is the election secret key for the election with configuration `ec`; note that this is only useful for subprotocols in isolation when we are not modeling threshold decryption.
- `!BallotStyle(ec, ballot_style, %i)` indicates that a ballot style (`ballot_style`) has been defined as valid for the election with configuration `ec`; `%i` is a sequence number and has no other semantic meaning.
- `!EligibleVoter(ec, $voter_identity, ballot_style, %i)` indicates that a voter with _real_ identity `voter_identity` is eligible to vote in the election with configuration `ec` using ballot style `ballot_style`; `%i` is a sequence number and has no other semantic meaning.
- `!EASPublicKey(ec, key)` indicates that the election administration server for the election with configuration `ec` has public signing key `key`.
- `!EASSecretKey(ec, key)` indicates that the election administration server for the election with configuration `ec` has secret signing key `key`.

### Trustee Setup

- `!TAS_Secret_Signing_Key(key)` indicates that the trustee administration server has secret signing key `key`.
- `!TAS_Public_Signing_Key(key)` indicates that the trustee adminsitration server has public signing key `key`.
- `!TAS_ElectionSetup_Complete(ec)` indicates that the trustee administration server has completed the trustee key setup for the election with configuration `ec`.
- `!Trustee(trustee_name)` indicates that the trustee with name `trustee_name` (assumed to be a Tamarin public value) is a valid trustee.
- `!Trustee_Secret_Keys(trustee_name, signing_key, encryption_key)` indicates that the trustee with name `trustee_name` has secret signing key `signing_key` and secret encryption key `encryption_key`.
- `!Trustee_Public_Keys(trustee_name, signing_key, encryption_key)` indicates that the trustee with name `trustee_name` has public signing key `signing_key` and public encryption key `encryption_key`.
- `!Trustee_ElectionSetup(trustee_name, ec)` indicates that the trustee with name `trustee_name` is a trustee for the election with configuration `ec`.

### Election Key Generation

- `!ElectionPublicKey(key)` indicates that `key` is the election public key generated by the trustees. Note that this is duplicative of `ElectionPublicKey(ec, key)`, above, because the trustees don't have a concept of multiple elections happening simultaneously, and are only generating one election public key in this subprotcol.
- `!Trustee_ElectionPublicKey(trustee_name, key)` indicates that the trustee with name `trustee_name` believes the election public key to be `key`.
- `!Trustee_ElectionPublicKey_Agreement(trustee_name, key)` indicates that the trustee with name `trustee_name` has observed that all the trustees believe the election public key to be `key`.
- `!Trustee_Private_Share(trustee_name, private_share)` indicates that the trustee with name `trustee_name` used the private key share `private_share` when generating its part of the election public key.

### Voter Authentication

- `!DBB_Voter_Authorized(ec, signed_msg_auth, pseudonym, pk_voter, ballot_style, %i)` indicates that the digital ballot box believes the voter with pseudonym `pseudonym` to be authorized to vote a ballot with ballot style `ballot_style` in the election with configuration `ec`, using the public key `pk_voter` and authorized by the authorization message `signed_msg_auth` (which will be posted to the public bulletin board in the event that the voter actually submits a ballot with key `pk_voter`); `%i` is a sequence number and has no othre semantic meaning.
- `!VA_Eligible_Voter(ec, va_id, pseudonym, sk_voter, ballot_style)` indicates that the voting application with voting session ID `va_id` is acting on behalf of the voter with pseudonym `pseudonym` and secret key `sk_voter` to vote a ballot of style `ballot_style` in the election with configuration `ec`.

### Ballot Submission

- `!DBB_Posted_Ballot(ec, va_id, pseudonym, bb_entry, %i)` indicates that the digital ballot box has posted a bulletin board entry `bb_entry` containing a ballot submitted by the voter with pseudonym `pseudonym`, using the voting application with voting session ID `va_id`, in the election with configuration `ec`; `%i` is a sequence number and has no other semantic meaning.
- `!VA_Submitted_Ballot(ec, va_id, ballot, cryptograms, r, tracker)` indicates that the voting application with voting session ID `va_id` generated the cryptograms `cryptograms` using randomness `r` from plaintext ballot `ballot` for the election with configuration `ec`, submitted them to the DBB, and received a ballot tracker `tracker` in response.
