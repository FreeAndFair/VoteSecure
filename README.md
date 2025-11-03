# VoteSecure

This is the primary repository for [Free & Fair](https://freeandfair.us/)’s work on the [Tusk Philanthropies](https://tuskphilanthropies.org/)/Free Democracy Foundation [Mobile Voting Project](https://mobilevoting.org/), which is being carried out using the [Rigorous Digital Engineering](https://rde.freeandfair.us/) methodology. The goal of this work is to develop the cryptographic core of an end-to-end verifiable Internet voting (E2E-VIV) system.

## Information

- The project's [license](./LICENSE.md), [code of conduct](./CODE_OF_CONDUCT.md), [responsible disclosure guidelines](./SECURITY.md), and [contribution guidelines](./CONTRIBUTING.md) are available in separate documents.
- The [frequently asked questions (FAQ) document](https://github.com/FreeAndFair/MobileVotingCoreCryptography/releases/download/latest/faq.pdf), available in our [GitHub releases](https://github.com/FreeAndFair/MobileVotingCoreCryptography/releases), contains answers to many questions we have been asked about the project.
- The [team documentation](./docs/team.md) contains information for the project team (some of which is also applicable to other contributors) about how development is carried out in this and related project repositories, team communication standards, etc.
- The [continuous integration/deployment/verification documentation](./docs/ci_cd_cv.md) contains information about what artifacts are checked/created/verified in the repository (and related repositories) via continuous integration, deployment, and verification.
- In order to understand the modeling we are focused on at a high level, a white paper called "[Refinements between High-Level Models](https://github.com/FreeAndFair/MobileVotingCoreCryptography/releases/download/latest/refinements_paper.pdf)" is available in our [GitHub releases](https://github.com/FreeAndFair/MobileVotingCoreCryptography/releases).  Its target audience is computer scientists/mathematicians who have a basic understanding of rigorous modeling.
- Our [concept of operations (CONOPS)](./docs/conops/conops.md) provides a high-level description of an E2E-VIV system that uses the cryptographic core library being developed here; note that Free & Fair is _not_ developing such a system, but only the cryptographic core library.
- The [static version of our threat model](https://github.com/FreeAndFair/MobileVotingCoreCryptography/releases/download/latest/threat-model.pdf) is available in our [GitHub releases](https://github.com/FreeAndFair/MobileVotingCoreCryptography/releases).

## Repository Layout

The repository is broken into several parts, and each part has its own README (or other) files that explain its contents:

- [assurance](./assurance) contains the AdvoCATE assurance case and its associated files.
- [docker](./docker) contains files required to build the various Docker images.
- [docs](./docs) contains documents related to the project, including protocol documentation.
- [examples/needham-schroeder](./examples/needham-schroeder) contains a partial example of a small cryptographic protocol implemented using the RDE process.
- [implementations/rust](./implementations/rust) contains the VoteSecure protocol library implementation.
- [models](./models) contains all the RDE models, including the domain model, feature model, threat model, formal protocol model, and SysML system model.
