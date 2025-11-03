# Ballot Casting Subprotocol

This subprotocol defines the interaction between the voting application and the digital ballot box to mark as cast a previously submitted ballot.

## Phase 1: Request to Cast

### Cast Request Message

sender
: Voting Application (VA)

recipient
: Digital Ballot Box (DBB)

purpose
: Inform the digital ballot box which ballot the voting application is requesting to cast and provide a non-reputable digital attestation that the voting application has requested this action take place.

***structure***

```rust
struct CastReqMsgData {
  election_hash : ElectionHash,
  voter_pseudonym : VoterPseudonym,
  voter_verifying_key : VerifyingKey,
  ballot_tracker : BallotTracker,
}

struct CastReqMsg {
  data : CastReqMsgData,
  signature : Signature,
}
```

- `election_hash`: The hash of the unique election configuration item.
- `voter_pseudonym`: The unique identifier for the voter.
- `voter_verifying_key`: The verifying key associated with this voting session.
- `ballot_tracker`: The unique identifier of the ballot cryptogram to be cast.
- `data`: The data being signed (contains the election hash, voter pseudonym, voter verifying key, and ballot tracker).
- `signature`: A digital signature created over the serialized contents of the `data` field by the voting application's signing key.

### Cast Request Checks

1. The `election_hash` is the hash of the election configuration item for the current election.
2. The `voter_pseudonym` and `voter_verifying_key` match a current (i.e., the most recent for that `voter_pseudonym`) `AuthVoterMsg` from the EAS.
3. The `ballot_tracker` matches a previously published `BallotSubBulletin` entry on the public bulletin board and the `election_hash`, `voter_pseudonym`, and `voter_verifying_key` from this message match the corresponding elements of the `BallotSubBulletin` entry.
4. There are no previously published `BallotCastBulletin` entries on the public bulletin board with the same `voter_pseudonym`.
5. The `BallotSubBulletin` corresponding to the `ballot_tracker` is the most recent such entry on the bulletin board with this `voter_pseudonym`.
6. The `signature` is a valid signature over the serialized contents of the `data` field signed by the signing key corresponding to `voter_verifying_key`.

### Voter Authorization Bulletin

Once the *Cast Request Checks* have been completed successfully, the digital ballot box appends this entry to the public bulletin board. This entry serves to permanently record the authorization of a signing key and voter pseudonym provided by the election administration server using a tamper evident data structure. For clarification, this is the same voter authorization message previously received from the election administration server, which was used both when validating ballot submissions and when validating the cast request. The voter authorization was not published to the bulletin board until now, after all casting checks have been completed and directly prior to a ballot casting, so as to support multiple authorizations yet ensure only one key is ever authorized when casting a ballot to aid in universal verifiability.

***structure***

```rust
struct VoterAuthBulletinData {
  election_hash : ElectionHash,
  timestamp : u64,
  authorization : AuthVoterMsg,
  previous_bb_msg_hash : String,
}

struct VoterAuthBulletin {
  data : VoterAuthBulletinData,
  signature : String,
}
```

- `election_hash`: The hash of the unique election configuration item.
- `timestamp`: The timestamp of when the DBB processed the submission (Unix timestamp in seconds since epoch).
- `authorization`: The signed voter authorization message from the EAS.
- `previous_bb_msg_hash`: The hash of the last message posted to the bulletin board.
- `data`: The data being signed (contains the election hash, timestamp, authorization, and previous bulletin board message hash).
- `signature`: A digital signature created over the serialized contents of the `data` field by the digital ballot box signing key.

### Ballot Cast Bulletin

Once the *Voter Authorization Bulletin* has been posted, the casting of the selected ballot can proceed. The digital ballot box appends this entry to the public bulletin board. This entry officially casts the ballot on behalf of the voter for this election. this process can only occur once per voter and is unable to be canceled once completed. The casting bulletin serves to permanently record the voter's ballot choices as cast using a tamper evident data structure.

***structure***

```rust
struct BallotCastBulletinData {
  election_hash : ElectionHash,
  timestamp : u64,
  ballot : SignedBallotMsg,
  cast_intent : CastReqMsg,
  previous_bb_msg_hash : String,
}

struct BallotCastBulletin {
  data : BallotCastBulletinData,
  signature : String,
}
```

- `election_hash`: The hash of the unique election configuration item.
- `timestamp`: The timestamp of when the DBB processed the submission (Unix timestamp in seconds since epoch).
- `ballot`: The signed ballot message submitted earlier matching the ballot tracker in the cast request.
- `cast_intent`: The signed voter cast request message from the VA.
- `previous_bb_msg_hash`: The hash of the last message posted to the bulletin board.
- `data`: The data being signed (contains the election hash, timestamp, ballot, cast intent, and previous bulletin board message hash).
- `signature`: A digital signature created over the serialized contents of the `data` field by the digital ballot box signing key.

## Phase 2: Confirm Cast

Once the digital ballot box has validated the cast request against the appropriate validation checks and written the cast message to the public bulletin board this phase begins.

### Cast Confirmation Message

sender
: Digital Ballot Box (DBB)

recipient
: Voting Application (VA)

purpose
: Confirm to the voting application that the ballot has been successfully cast and provide the voting application with a locater for the public bulletin board message where the casting message was written.

***structure***

```rust
struct CastConfMsgData {
  election_hash : ElectionHash,
  ballot_sub_tracker : BallotTracker,
  ballot_cast_tracker : Option<BallotTracker>,
  cast_result : (bool, String),
}

struct CastConfMsg {
  data : CastConfMsgData,
  signature : Signature,
}
```

- `election_hash`: The hash of the unique election configuration item.
- `ballot_sub_tracker`: The unique identifier of the submitted ballot bulletin on the PBB.
- `ballot_cast_tracker`: The optional unique identifier of the casting bulletin on the PBB (present only if casting succeeded).
- `cast_result`: A tuple containing a boolean indicating if the cast was successful and a string with result details.
- `data`: The data being signed (contains the election hash, ballot submission tracker, ballot cast tracker, and cast result).
- `signature`: A digital signature created over the serialized contents of the `data` field by the digital ballot box's signing key.

## Voting Application Process Diagram

```mermaid
    stateDiagram-v2
      submit_request : Send **Submit Signed Ballot Message**
      receive_confirm : Receive **Return Ballot Tracker Message**
      complete : **Success** Ballot Cryptogram Cast and Message Locator Received
      error : **Failure** Protocol Aborted with Error Message


      [*] --> submit_request

      submit_request --> receive_confirm
      submit_request --> error : Timeout Exceeded Error
      receive_confirm --> complete
      receive_confirm --> error : Timeout Exceeded Error
      receive_confirm --> error : Invalid Signature Error
      receive_confirm --> error : Incorrect BallotID Error
      receive_confirm --> error : Invalid Message Locator Error

      complete --> [*]
      error --> [*]
```

## Digital Ballot Box Process Diagram

```mermaid
    stateDiagram-v2
      receive_request : Receive **Submit Signed Ballot Message**
      send_confirm : Send **Return Ballot Tracker Message**
      complete : **Success** Ballot Cryptogram Cast and Message Locator Received
      error : **Failure** Protocol Aborted with Error Message


      [*] --> receive_request

      receive_request --> send_confirm
      receive_request --> error : Timeout Exceeded Error
      receive_request --> error : Invalid Signature Error
      receive_request --> error : Invalid BallotID Error
      receive_request --> error : Signature Mismatch Cryptogram Error
      receive_request --> error : Invalid Cryptogram Error
      send_confirm --> complete

      complete --> [*]
      error --> [*]
```
