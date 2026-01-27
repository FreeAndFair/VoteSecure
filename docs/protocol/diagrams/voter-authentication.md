# Voter Authentication Subprotocol Sequence Diagram

``` mermaid
sequenceDiagram
    title Voter Authentication Subprotocol

    participant VA as "Voting Application"
    participant UserAgent as "Voter's User Agent/Browser"
    participant EAS as "Election Admin Server"
    participant AS as "Authentication Service (AS)"
    participant DBB as "Digital Ballot Box"

    VA->>EAS: Request Authentication for Voter (PublicKey: P)
    activate VA
    activate EAS
    EAS->>AS: Initiate Authentication Request
    activate AS
    AS-->>EAS: Provide Session Info (SessionID: S, AuthToken: T)
    # AS is now ready for the user authentication step via redirect

    EAS->>VA: Provide Auth Token (Token: T, For PublicKey: P)

    Note over VA: Prepare redirection for user
    VA->>UserAgent: Redirect User to AS Authentication URL (embedding Token T)
    deactivate VA ## VA waits for callback/redirect completion
    activate UserAgent

    UserAgent->>AS: Access Authentication URL (Token: T)
    Note over AS: User performs authentication steps (e.g., login, MFA)
    # Upon completion, AS redirects the UserAgent back to a pre-registered VA endpoint
    AS-->>UserAgent: Authentication Complete (Redirect back to VA Callback URL)
    deactivate AS

    UserAgent->>VA: Callback to VA (signaling completion for Token T)
    deactivate UserAgent
    activate VA

    VA->>EAS: Notify: Authentication Process Finished (Token: T)

    EAS->>AS: Query Authentication Result (SessionID: S)
    activate AS
    AS-->>EAS: Report Authentication Result for Session S (Status: Success) ## Happy Path: Authentication Succeeded
    deactivate AS

    # --- Happy Path Steps ---
    Note over EAS: Look up voter info, Check Eligibility using PublicKey P ## Happy Path: Voter is Eligible
    EAS->>DBB: Authorize PublicKey P for Submission/Casting (Ballot Type: ...)
    activate DBB
    DBB->>DBB: Append Record to PBB: 'PublicKey P Authorized...'
    EAS->>VA: Auth Success & Eligible (Elections: [...], For PublicKey: P)
    Note over VA: Display pseudonym to authenticated voter
    deactivate DBB
    # --- End Happy Path Steps ---

    deactivate EAS
    deactivate VA
```
