# Ballot Check Subprotocol Sequence Diagram

```mermaid
sequenceDiagram
        participant Voter
    box rgb(255, 235, 204) Internet / Election Admin Network
        participant BCA as Ballot Checking App
        participant VA as Voting Application
        participant DBB as Digital Ballot Box
        participant PBB as Public Bulletin Board
    end

    Note over Voter, BCA: Voter enters Ballot Tracker ID (I) into BCA.
    activate BCA
    BCA->>PBB: Request BallotSubBulletin (ID I)
    PBB->>BCA: Send BallotSubBulletin (ID I)
    BCA->>BCA: Generate Key Pair (BCA_PubKey, BCA_PrivKey)
    BCA->>Voter: Display generated Public Key (BCA_PubKey)
    BCA->>+DBB: Send Check Request (ID I, BCA_PubKey, Signature)
    Note over BCA: Request sent, displays PubKey, waits for data.

    activate DBB
    DBB->>DBB: Verify Request Signature using BCA_PubKey
    DBB->>+VA: Forward Check Request (ID I, BCA_PubKey)
    deactivate DBB

    activate VA
    VA->>Voter: Display Check Request & Public Key from BCA
    Note over Voter: Voter compares PubKey on VA screen with PubKey on BCA screen.
    Voter->>VA: Approve Check Request
    VA->>VA: Retrieve Original Ballot Randomizers (R) for ID I
    VA->>VA: Encrypt Randomizers (R) using BCA_PubKey
    VA->>+DBB: Send Encrypted Randomizers for Ballot I
    deactivate VA

    activate DBB
    DBB-->>BCA: Forward Encrypted Randomizers
    deactivate DBB

    activate BCA
    BCA->>BCA: Receive Encrypted Randomizers
    BCA->>BCA: Decrypt Randomizers using BCA_PrivKey to recover R
    BCA->>BCA: Decrypt Ballot Choices using R, received BallotSubBulletin, ElectionPublicKey
    BCA->>Voter: Display Decrypted Ballot Choices

   Note over Voter, BCA: Voter manually reviews the displayed choices<br/>and compares them with the choices they remember<br/> making in the Voting Application.

    Voter->>BCA: (only if ballot is cast) Check for Cast Ballot on Bulletin Board
    BCA->>Voter: Display Cast Ballot Data from Bulletin Board

    deactivate BCA


```
