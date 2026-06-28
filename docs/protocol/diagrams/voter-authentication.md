# Voter Authentication Subprotocol Sequence Diagram

``` mermaid
sequenceDiagram
    title Voter Authentication Subprotocol

    participant VA as "Voting Application"
    participant UserAgent as "Voter's User Agent/Browser"
    participant EAS as "Election Admin Server"
    participant AS as "Authentication Service (AS)"

    VA->>EAS: Request Authentication for Voter (PublicKey: P)
    activate VA
    activate EAS
    EAS->>AS: Initiate Authentication Request
    activate AS
    AS-->>EAS: Provide Session Info (SessionID: S, AuthToken: T)
    %% AS is now ready for the user authentication step via redirect

    EAS->>VA: Provide Auth Token (Token: T, For PublicKey: P)

    Note over VA: Prepare redirection for user
    VA->>UserAgent: Redirect User to AS Authentication URL (embedding Token T)
    %% VA waits for callback/redirect completion
    deactivate VA
    activate UserAgent

    UserAgent->>AS: Access Authentication URL (Token: T)
    Note over AS: User performs authentication steps (e.g., login, MFA)
    %% Upon completion, AS redirects the UserAgent back to a pre-registered VA endpoint
    AS-->>UserAgent: Authentication Complete (Redirect back to VA Callback URL)
    deactivate AS

    UserAgent->>VA: Callback to VA (signaling completion for Token T)
    deactivate UserAgent
    activate VA

    VA->>EAS: Notify: Authentication Process Finished (Token: T)

    EAS->>AS: Query Authentication Result (SessionID: S)
    activate AS
    %% Happy Path: Authentication Succeeded
    AS-->>EAS: Report Authentication Result for Session S (Status: Success)
    deactivate AS

    %% --- Happy Path Steps ---
    %% Happy Path: Voter is Eligible
    Note over EAS: Look up voter info, Check Eligibility using PublicKey P
    EAS->>VA: Auth Success & Eligible (Elections: [...], For PublicKey: P)
    Note over VA: Display pseudonym to authenticated voter
    %% --- End Happy Path Steps ---

    deactivate EAS
    deactivate VA
```
