# Reporting Security Issues

Free & Fair takes the security of our software seriously. We appreciate your efforts to responsibly disclose your findings, and will make every effort to publicly acknowledge your contributions either with specific attribution or anonymously (as you choose).

## Scope

This project implements a cryptographic library that is meant to serve as the core of an end-to-end verifiable Internet voting system, rather than implementing an actual end-to-end verifiable Internet voting system. As such, most generic security vulnerabilities related to systems deployed on the Internet are not in scope. For example, while a voting system implemented using this cryptographic library might be vulnerable to attacks like distributed denial of service (DDoS) or DNS poisoning, the cryptographic library _itself_ could only be vulnerable to such attacks if the implementation directly exposes functionality to or relies on the Internet.

It is, of course, possible that some aspects of the library's design may unintentionally expose systems that use the library correctly to such attacks, or that the library's safeguards against incorrect usage may be insufficient to prevent straightforward usage mistakes from causing such exposure. We therefore do not categorically rule out any class of Internet security vulnerability for reporting, though we reserve the right to determine that any specific such vulnerability reported is indeed out of the library's scope.

The project's [threat model](./models/threat-model) (the most recent static version of which is available in the [latest release](https://github.com/FreeAndFair/VoteSecure/releases/tag/latest)) describes in detail the security threats we have identified and those that we have already deemed out of scope. Ideally, any vulnerability report you write should refer directly to the threat model (including the specific revision of the repository containing the threat model being referenced), either by indicating the threats in the model to which the report relates, or by pointing out some aspect of the threat model that is incomplete.

For the safety of the project, the Internet at large, and you as a security researcher, and to ensure that security reports are actually related to security, the following are explicitly out of scope:

- Findings derived primarily from social engineering (e.g., phishing);
- Findings isolated to third-party dependencies;
- Findings isolated to systems that incorporate the cryptographic library, rather than the cryptographic library itself;
- Findings derived from actual network-level denial of service (DoS/DDoS) attacks (theoretical findings are OK—though see above for why they are not, in practice, likely to be in scope—but practical findings obtained through actual network disruption are not); and
- Spelling, grammatical, and typographical errors that do not _directly_ impact security; such non-security errors should be submitted as public GitHub issues (see [CONTRIBUTING.md](./CONTRIBUTING.md)).

## Reporting

If you believe you have found an in-scope security vulnerability related to the artifacts in this repository, please **do not file a public GitHub issue**. Instead, file a security report using the GitHub Security Advisory ["Report a Vulnerability"](https://github.com/FreeAndFair/VoteSecure/security/advisories/new) tab.

The project team will send a response within 72 hours indicating the next steps in handling your report. After this initial response, the team will keep you informed of the progress toward a fix and full announcement, and may ask for additional information or guidance.

Please report security vulnerabilities in any third-party dependencies to the person or team maintaining the dependency, following their reporting process.
