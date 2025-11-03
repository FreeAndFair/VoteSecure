# Continuous Integration, Deployment, and Verification (CI/CD/CV)

This document contains general information about the continuous integration (CI), continuous deployment (CD), and continuous verification (CV) practices of this project, and specific information about what artifacts are currently, and are planned to be, checked, generated, and verified using CI/CD/CV processes.

## Continuous Integration

Continuous integration is meant to check that everything in the repository (that can be reasonably checked) has correct syntax, builds correctly without errors (and, depending on how pedantic we are for any given artifact, without warnings), and fulfills any other requirements of the project or the repository that can be automatically checked. Examples include ensuring that LaTeX documents can compile and generate PDFs, ensuring that Lando and Clafer models can be parsed, ensuring that Clafer models can generate instances, etc. Continuous integration processes are typically run on every commit to a pull request branch, and on every commit added to `main` or a release branch.

The artifacts that are currently subject to continuous integration, the checks that are done, and the mechanisms by which that occurs are:

- Lando files (`*.lando`) are checked for syntactic validity, by running `lando validate` within our [PLE docker container](../docker/de-ple-e2eviv). This occurs for changed Lando files in pull request commits (via GitHub action workflow [Test Validity of Changed Lando Files](../.github/workflows/test-validity-of-changed-lando-files.yml)) and for all Lando files in the repository on every push to `main` (via GitHub action workflow [Test Validity of Lando Files](../.github/workflows/test-validity-of-lando-files.yml)).
- Clafer files (`*.cfr`) are checked for syntactic validity, by running `clafer` within our [PLE docker container](../docker/de-ple-e2eviv). This occurs for changed Clafer files in pull request commits (via GitHub action workflow [Test Validity of Changed Clafer Files](../.github/workflows/test-validity-of-changed-clafer-files.yml)) and for all Clafer files in the repository on every push to `main` (via GitHub action workflow [Test Validity of Clafer Files](../.github/workflows/test-validity-of-clafer-files.yml)).
- All targets of the [Clafer feature model](../models/feature-model)'s [makefile](../models/feature-model/makefile) are built (again, within our [PLE docker container](../docker/de-ple-e2eviv)) on every pull request commit that changes anything within the feature model's directory and on every push to `main` (via GitHub action workflow [Run Makefile for Clafer Model](../.github/workflows/run-makefile-for-clafer-model.yml)).
- All targets of the [threat model](../models/threat_model)'s [makefile](../models/threat-model/Makefile) are built on every commit that changes anything within the threat model's directory. This ensures that the threat model database can be built, and that the static threat model document can be built. The threat model diagrams are _not_ regenerated during continuous integration, because some of them require macOS and OmniGraffle to build, and their rendered versions are stored in the repository.
- The [Tamarin model](../models/cryptography/tamarin/) is checked for syntactic correctness and many of its properties are verified any time anything in its directory hierarchy changes.
- All buildable LaTeX documents in the repository are rebuilt on every commit that changes anything in them.
- All Cryptol code is checked for syntactic correctness and its properties are verified.
- All Rust code is checked for syntactic correctness, a subset of its tests (suitable for running in GitHub CI) is run, and many other checks (e.g., lints, software supply chain verifications) are performed every time anything in the [Rust workspace](../implementations/rust/workspace/) is updated.

## Continuous Deployment

Continuous deployment is meant to ensure that a set of artifacts both can be generated and is made available for download (rather than forcing individuals to regenerate it themselves). Such a set of artifacts for a project is called a "release" (though in most cases, for this project, it will be a "development release" that is just a checkpoint of the current `main`). These generated artifacts may include rendered documents (e.g., PDFs from LaTeX sources, PDFs or Markdown documents from Lando sources), executable code, etc.

LaTeX documents and the threat model are currently subject to continuous deployment, and the repository for the [Free & Fair Coding Standards](https://github.com/FreeAndFair/CodingStandards), a multi-file LaTeX document, deploys a rendered version of the code standards to its [Latest release](https://github.com/FreeAndFair/CodingStandards/releases/tag/latest) every time a change to the document is pushed to `main`.

## Continuous Verification

Continuous verification is meant to ensure that the artifacts in the repository satisfy some correctness criteria, via execution of either generated or hand-written test suites and static formal verification routines. We currently do not have any artifacts in the repository that are subject to continuous verification. The artifacts on which we currently perform continuous verification are:

- Cryptol implementations of cryptographic algorithms
- Tamarin descriptions of cryptographic protocols
- Rust implementations of the core library
