# VoteSecure Change Log

This change log lists changes to VoteSecure with each released version. It is not comprehensive (i.e., it does not include non-material changes like fixes for typographical errors, updates to the continuous integration scripts, etc.). Starting with version 1.4, the change log explicitly calls out the impact of each change on integrators.

## [Version 1.4](https://github.com/FreeAndFair/VoteSecure/releases/tag/v1_4) - ?? July 2026

- replaced the digital ballot box's internal storage with a design where the voter authorization issued by the election administration server is sent only to the voting application, which includes it in both its ballot submission and ballot casting messages; the digital ballot box now holds no persistent storage of its own, answering every check (prior authorization, prior submission, prior cast) directly from the public bulletin board
  - *Impact:* The digital ballot box actor's constructor no longer takes a storage argument, and the `DBBStorage` trait has been removed. The voter authorization message (formerly `AuthVoterMsg`) is now a `VoterAuthorization` token, defined in the `elections` module, and is sent to the voting application upon successful authentication; it must be retained by the voting application and included with ballot submissions and cast requests. The election administration server no longer communicates with the digital ballot box.
- renamed `HandTokenMsg`/`HandTokenMsgData` to `AuthServiceTokenMsg`/`AuthServiceTokenMsgData` (and the corresponding `ProtocolMsg` variant) in the voter authentication specification, for additional clarity about the message's contents
  - *Impact:* Any code referencing the old names must be updated.
- changed the data structures that represent bulletin board entries ("bulletins") so that custom bulletin types can be added by integrators
  - *Impact:* Any code that used the v1.0-v1.3 bulletin types must be rewritten to use the new bulletin types.
- added a check at ballot submit time for a cast ballot with the same voter pseudonym
  - *Impact:* An attempt to submit a ballot for a voter who has already cast a ballot will fail at the protocol level immediately, rather than needing to be detected/prevented at the application level or causing a failure at attempted cast time.
- removed Stateright from production builds; it is only used for testing, but was previously linked into all builds
  - *Impact:* None

## [Version 1.3](https://github.com/FreeAndFair/VoteSecure/releases/tag/v1_3) - 15 May 2026

- added documentation (in the CONOPS and relevant protocol specifications) to clarify that trustee public keys are expected to be broadly publicly known so that trustee signatures are publicly verifiable, and that trustee signatures for the election public key should be posted to the public bulletin board
- renamed several Rust structures to increase understandability; this does not change any SDK functionality or protocol descriptions but does break the API, necessitating the 1.2 → 1.3 version bump
- added `rustdoc` comments to public structures/functions in the `protocol` crate that did not previously have them, and updated many existing `protocol` crate documentation comments; aside from fixing some minor issues with existing comments, documentation comments were not updated in the `cryptography` crate as application developers typically do not program directly against it

## [Version 1.2](https://github.com/FreeAndFair/VoteSecure/releases/tag/v1_2) - 5 May 2026

- updated Rust `rand` package to 0.10.1 to address [RUSTSEC-2026-0097](https://rustsec.org/advisories/RUSTSEC-2026-0097)
- updated ballot submission protocol documentation to match implementation details
- fixed a formatting error in the CONOPS
- fixed comment syntax issues in the Mermaid diagrams for the cryptographic protocols

## [Version 1.1.1](https://github.com/FreeAndFair/VoteSecure/releases/tag/v1_1_1) - 10 April 2026

- updated threat model and procedures to address security advisories [GHSA-v43c-fm6q-w8f8](https://github.com/FreeAndFair/VoteSecure/security/advisories/GHSA-v43c-fm6q-w8f8) and [GHSA-w7jj-jfcc-gf89](https://github.com/FreeAndFair/VoteSecure/security/advisories/GHSA-w7jj-jfcc-gf89)
- removed the Cryptol compiler and all references thereto, as we were not actually using it to generate code
- fixed a minor type inference issue that prevented the Cryptol model from working with current versions of Cryptol
- added continuous integration for the Isabelle E2E-VIV session
- reimplemented the browsable view of the threat model as a completely local HTML/JavaScript document with additional views, cross-linking, and many other quality-of-life enhancements; this is now part of each release, in addition to the PDF version of the threat model ([direct download link](https://github.com/FreeAndFair/VoteSecure/releases/download/latest/threat-model.html))
- reimplemented CI/CD/CV orchestration across the repository
- updated Tamarin proof scripts to support a minor change necessitated by Tamarin 1.12's modified handling of functions declared by builtins
- fixed various spelling and typographical errors in the repository

## [Version 1.1](https://github.com/FreeAndFair/VoteSecure/releases/tag/v1_1) - 6 February 2026

- implemented mitigations for [a reported clash attack](https://github.com/FreeAndFair/VoteSecure/issues/6), which was originally reported as a security advisory; the implemented mitigations are described in the issue
- updated the protocol descriptions and diagrams to include the implemented mitigations
- updated the threat model to include the reported clash attack and its mitigations, and did some additional threat model cleanup
- implemented a missing check for a matching ballot tracker within the voting application's check procedure
- modified cryptographic context function names and usage for clarity
- reimplemented the threat model in Python and provided an additional graph visualization for it

## [Version 1.0 (with Updated Documentation)](https://github.com/FreeAndFair/VoteSecure/releases/tag/v1_0_updated_docs) - 20 November 2025

- brought documentation, specifications, and diagrams up-to-date with the code in the initial release

## [Version 1.0](https://github.com/FreeAndFair/VoteSecure/releases/tag/v1_0) - 14 November 2025

- initial release
