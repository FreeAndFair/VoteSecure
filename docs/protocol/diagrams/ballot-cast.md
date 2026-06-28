# Ballot Cast Subprotocol Sequence Diagram

```mermaid
sequenceDiagram
    participant Voter

    box rgb(255, 235, 204) Internet / Election Admin Network
        participant VA as Voting Application
        participant DBB as Digital Ballot Box
        participant PBB as Public Bulletin Board
    end

    Voter ->> VA: Initiate Cast Ballot (Selects submitted ballot)
    activate VA
    Note over VA: Prepare cast request for specific BallotTracker

    %% Send request to DBB
    VA ->> +DBB: CastRequest(BallotTracker)

    Note right of DBB: Receive cast request
    DBB->>DBB: Verify BallotTracker exists & is eligible to be cast (see spec for details)
    DBB->>DBB: Prepare PBB Cast Record data (e.g., BallotTracker, Timestamp)
    %% Post evidence to PBB
    DBB ->> +PBB: Write Cast Record data

    Note right of PBB: Receive record for posting
    PBB->>PBB: Append Cast Record data to bulletin board log
    PBB->>PBB: Generate MessageLocator for the appended record
    %% Return locator confirming PBB post
    PBB -->> -DBB: MessageLocator

    Note right of DBB: Receive PBB locator
    %% Confirm cast to VA, include locator
    DBB -->> -VA: (BallotTracker, MessageLocator)

    Note over VA: Receive confirmation and PBB locator
    VA -->> Voter: Display Cast Confirmation Text, PBB MessageLocator, and BallotTracker
    deactivate VA
```
