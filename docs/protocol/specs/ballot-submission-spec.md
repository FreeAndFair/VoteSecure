# Ballot Submission Subprotocol

This subprotocol covers the process where the Voting Application sends the encrypted and signed ballot to the Digital Ballot Box, which verifies it, records it on the Public Bulletin Board, and returns a tracker.

## Phase 1: Ballot Preparation and Submission

### Ballot Preparation (Internal VA Process)

Before sending the ballot, the Voting Application performs the necessary cryptographic operations internally:

1. The application maps the voter selections to a plaintext ballot encoding based on the ballot style.
2. It generates the randomizers needed to encrypt the plaintext ballot.
3. It encrypts the plaintext ballot using Naor-Yung with the Election Public Key (Y), producing a single `BallotCiphertext` (with proof).
4. Finally, it signs the resulting ballot data (`SignedBallotMsgData`, below), using its session-specific signing key corresponding to the `voter_verifying_key` generated during authentication.

### Submit Signed Ballot Message

sender
: Voting Application (VA)

recipient
: Digital Ballot Box (DBB)

purpose
: This message submits to the digital ballot box a signed ballot cryptogram encrypted for the election public key.

***structure***

```rust
struct SignedBallotMsgData {
  voter_authorization : VoterAuthorization,
  ballot_cryptogram : BallotCryptogram,
}

struct SignedBallotMsg {
  data : SignedBallotMsgData,
  signature : Signature,
}

struct BallotCryptogram {
  ballot_style : BallotStyle,
  ciphertext : BallotCiphertext,
}
```

- `voter_authorization`: An authorization token, signed by the EAS, containing the hash of the unique election configuration item, the voter's pseudonym (the unique identifier for the voter for the current election), the ballot style they are authorized to vote, and the verifying key associated with this voting session. See the voter authentication specification for more details about this data structure.
- `ballot_cryptogram`: The ballot cryptogram containing the encrypted ballot ciphertext.
- `data`: The data being signed (contains the election hash, voter pseudonym, voter verifying key, ballot style, and ballot cryptogram).
- `signature`: A digital signature created over the serialized contents of the `data` field by the signing key corresponding to the authorized voter verifying key.
- `ciphertext`: The Naor-Yung ciphertext containing the encrypted ballot.

channel properties
: The `signature` provides *integrity* and *authenticity* for the contents of the message. The `BallotCryptogram` ciphertexts provide confidentiality for the plaintext contest choices of the voter's ballot.

## Phase 2: Verification and Recording

### Submit Signed Ballot Checks

1. The `voter_authorization` is valid.
    1. Its signature verifies with the known EAS signature verification key for the current election.
    2. Its election hash is the hash of the election configuration item for the current election.
    3. Its timestamp is in the past.
2. The `signature` is a valid signature over the serialized contents of the `data` field (it verifies with the verifying key within the `voter_authorization`).
3. The `election_hash` is the hash of the election configuration item for the current election.
4. The ciphertext has a valid Naor-Yung proof.
5. The `ballot_style` in the `ballot_cryptogram` matches the `ballot_style` in the `voter_authorization`.
6. No cast ballot appears on the bulletin board with the voter pseudonym in the `voter_authorization`.
7. The ciphertext does not already exist on the bulletin board.

### Ballot Submission Bulletin

Once the *Submit Signed Ballot Checks* have been completed successfully, the digital ballot box appends this entry to the public bulletin board. This entry serves to permanently record the submission of a ballot cryptogram using a tamper evident data structure.

***structure***

```rust
struct BallotSubBulletinData {
  election_hash : ElectionHash,
  timestamp : u64,
  ballot : SignedBallotMsg,
  previous_bb_msg_hash : String,
}

struct BallotSubBulletin {
  data : BallotSubBulletinData,
  signature : String,
}
```

- `election_hash`: The hash of the unique election configuration item.
- `timestamp`: The timestamp of when the DBB processed the submission (Unix timestamp in seconds since epoch).
- `ballot`: The signed ballot message submitted earlier in full.
- `previous_bb_msg_hash`: The hash of the last message posted to the bulletin board.
- `data`: The data being signed (contains the election hash, timestamp, ballot, and previous bulletin board message hash).
- `signature`: A digital signature created over the serialized contents of the `data` field by the digital ballot box signing key.

## Phase 3: Confirmation

### Ballot Tracker Calculation (Internal DBB Process)

The DBB calculates the Ballot Tracker by taking a cryptographic hash of the entire PBB Ballot Submission Message exactly as it was written to the PBB.

### Return Ballot Tracker Message

sender
: Digital Ballot Box (DBB)

recipient
: Voting Application (VA)

purpose
: This message confirms successful submission of the ballot and provides the hash of the public bulletin board message which uniquely identifies this record on the public bulletin board.

***Structure***

```rust
struct TrackerMsgData {
  election_hash : ElectionHash,
  tracker : Option<BallotTracker>,
  submission_result : (bool, String),
}

struct TrackerMsg {
  data : TrackerMsgData,
  signature : Signature,
}
```

- `election_hash`: The hash of the unique election configuration item.
- `tracker`: The optional ballot tracker (hash of the BallotSubBulletin), present only if submission succeeded.
- `submission_result`: A tuple containing a boolean indicating if the submission was successful and a string with result details.
- `data`: The data being signed (contains the election hash, tracker, and submission result).
- `signature`: A digital signature created over the serialized contents of the `data` field by the digital ballot box signing key.

channel properties
: The `signature` provides *integrity* and *authenticity* for the contents of the message.

### Return Ballot Tracker Checks

1. The `election_hash` is the hash of the election configuration item for the current election.
2. If `tracker` is present, it corresponds to a `BallotSubBulletin` on the public bulletin board which contains the previously submitted `SignedBallotMsg`.
3. The `signature` is a valid signature over the serialized contents of the `data` field by the digital ballot box signing key.

### Confirmation Handling (Internal VA Process)

The VA receives the Return Ballot Tracker Message and stores the ballot_tracker. This tracker is then shown to the voter.

## Voting Application Process Diagram

```mermaid
    stateDiagram-v2
      submit_ballot : Send **Submit Signed Ballot Message**
      receive_tracker : Receive **Return Ballot Tracker Message**
      complete : **Success** Ballot Cryptogram Submitted and Tracker Received
      error : **Failure** Protocol Aborted with Error Message


      [*] --> submit_ballot

      submit_ballot --> receive_tracker
      submit_ballot --> error : Timeout Exceeded Error
      receive_tracker --> complete
      receive_tracker --> error : Timeout Exceeded Error
      receive_tracker --> error : Invalid Signature Error
      receive_tracker --> error : Invalid Tracker Error

      complete --> [*]
      error --> [*]
```

## Digital Ballot Box Process Diagram

```mermaid
    stateDiagram-v2
      receive_ballot : Receive **Submit Signed Ballot Message**
      send_tracker : Send **Return Ballot Tracker Message**
      complete : **Success** Ballot Cryptogram Submitted and Tracker Received
      error : **Failure** Protocol Aborted with Error Message


      [*] --> receive_ballot

      receive_ballot --> send_tracker
      receive_ballot --> error : Timeout Exceeded Error
      receive_ballot --> error : Invalid Signature Error
      receive_ballot --> error : Not Approved to Vote Error
      receive_ballot --> error : Invalid Cryptogram Error
      send_tracker --> complete

      complete --> [*]
      error --> [*]
```
