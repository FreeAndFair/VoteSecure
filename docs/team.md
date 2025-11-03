# Team Documentation

The following documents the mechanics (revision control practices, development environments, etc.) of how the team will develop this project and the communication mechanisms we will use during development.

IMPORTANT: This document refers to _internal_ repsitory URLs (and other restricted resources) and is meant for the core development team. If you are not part of the core development team, you should not be surprised when links in this document do not work for you.

## Coding Standards

- The [Free & Fair Coding Standards](https://github.com/FreeAndFair/CodingStandards/) specify guidelines for use of the various programming, specification, and verification languages used on the project. The latest version of the coding standards (as a PDF) is available [here](https://github.com/FreeAndFair/CodingStandards/releases/tag/latest).
- If you want to update the coding standards, the easiest way to do so is on Overleaf; ask for read/write access to the Overleaf project.

## GitHub Usage Standards

- This repository, as the “umbrella” repository for the project, will contain other repositories related to the project as submodules. Each repository in the project will, in turn, contain any necessary submodules. This repository will have continuous integration tasks related to the overall project, while each individual submodule will have its own self-contained continuous integration, deployment, and verification (CI/CD/CV) tasks (this applies recursively to submodules of submodules, etc.). [A separate document](ci_cd_cv.md) discusses CI/CD/CV in more detail, and should be updated as part of any pull request that modifies existing CI/CD/CV processes or adds new ones.
- The default branch of each repository related to this project will be called `main`, and will use branch protection. All releases will be either tags on this default branch, or, if it becomes necessary to backport changes to old releases, on specific release branches that start from `main` at the tag for that release and also use branch protection.
- GitHub issues should be created for _everything_ you are working on, even if it will not result in something being committed to the repository (e.g., doing literature reviews, which might result in a Google Doc or other non-repository artifact; learning a new tool, which might result in a recorded knowledge-sharing session). This ensures that your work is visible and trackable.
- All created issues should have short but meaningful names. Each issue must have appropriate metadata (labels, assignment to a column on the project board, associated milestone if applicable, etc.) and must contain sufficient information to provide clarity about (1) what the issue is meant to address and (2) what the conditions of satisfaction are for completing it. If work on an issue is expected to be long-term (more than a couple of weeks), it is considered an _epic_ (and should be tagged accordingly), and should  have explicit sub-issues that are of smaller scope and can be completed in shorter amounts of time.
  - _Note_: we recommend using GitHub's sub-issue functionality to create explicit sub-issues in an epic (less preferably, you could create a series of other issues and link them to the epic "by hand" by making a checklist of issue references). Creating a checklist without associated issues that have explicit statuses, assignments, etc. makes it more difficult to track work on the epic. For a regular issue that is expected to take a short time, checklists without associated issues are fine.
- The [project board](https://github.com/orgs/FreeAndFair/projects/2/views/2) ([alternate view including epic and informational items](https://github.com/orgs/FreeAndFair/projects/2/views/7)) is used to track open issues. We do not assign pull requests to columns on the project board, as that would create clutter (potentially doubling the number of board entries for active issues, if each pull request addresses one issue).
- All changes to `main` and any release branches, in any repository, must be made via pull requests (PRs).
  - Every PR should explicitly reference at least one issue in the issue tracker (this need not be in the same repository; a submodule PR can address an issue in the umbrella repository). If there is no appropriate issue in the issue tracker, one should be filed (preferably before filing the PR) so that the PR can reference it. Issue references within PRs should take advantage of GitHub’s built-in automations; for example, if a PR is meant to _close_ a specific issue `X`, its description should contain a line `Closes #X`, so that issue `X` is automatically closed when the PR is merged.
  - Every PR must be reviewed by at least one other team member and pass any active CI/CD checks for the repository before being merged. Note that it is _not_ required that a PR be reviewed by every reviewer tagged in the PR before being merged; however, team members should in general only tag reviewers from whom they want reviews (or acknowledgements/signoffs).
  - As an exception to the above rule, minor repository maintenance changes (e.g., adding a new file extension to a `.gitignore`, fixing a typographical error in a README) must be made via PRs for traceability, but may be merged without additional review as long as they pass CI/CD.
  - PRs (other than those that are minor or are immediately ready for merging) should initially be created as _drafts_, preferably as early as possible in the process of working on a new branch that will eventually be merged. This helps with situational awareness: open draft PRs allow others on the team to see what's being worked on and its current state, and provide a place for discussion about specific aspects of ongoing work. Once a draft PR is ready for review, the draft designation should be removed and reviewers should be tagged (if they hadn't been already).
  - Only a subset of team members will have permission to merge PRs.
- Commit messages should use the [Conventional Commits “standard”](https://www.conventionalcommits.org/en/v1.0.0/), with prefixes like `fix`, `feat`, `chore`, etc. We add a prefix `wip`, which is not in the standard Conventional Commits prefix set, for commits in draft PR branches that are expected to be squashed before merge to `main`, and a prefix `cosmetics` for cosmetic issues. We use a pre-commit hook to enforce this convention. Being consistent about commit message style will make the logs more readable and make release notes easier to generate. In particular, change logs can be automatically generated from commit messages using this convention.
- All commits that become part of releases must be _cryptographically signed_ (see [GitHub’s documentation on signing commits](https://docs.github.com/en/authentication/managing-commit-signature-verification/signing-commits)). This will be enforced on `main` and release branches as part of their branch protection. It will not be enforced on feature/development branches, but the changes will have to be signed before being merged to `main` or a release branch. Reviewed PRs need not be signed by the reviewers; it is sufficient that GitHub records the PR review results.
- The `main` branch and every release branch must have _linear history_ (i.e., no explicit merge commits). This means, in effect, that every pull request branch must have linear history and be rebased against its target branch before it is merged, and that merges must be “fast-forwards" that preserve commit hashes and signatures. Currently, such merges cannot be done via GitHub’s UI and must be done on the command line with `git merge --ff-only` (or within GitKraken with appropriate commands); however, command-line fast-forward merges _do_ work properly with respect to automatically closing GitHub pull requests that are merged, triggering automations like related issue closure, checking for compliance with branch protection rules, etc.
- Squashing of commits in PRs is at the discretion of the PR author, though it can be requested by reviewers. In general, commits that are made for work in progress (e.g., to preserve completed work when logging off for the day, to test the impact of a trivial change on continuous integration results) should be squashed once they are superseded, and all commits in a PR marked “ready for review” should be “meaningful” in that reviewers can look at the changes made in each commit and understand some rationale for why they were made. This is very much in the eye of the beholder, however; thus the discretion.
- When squashing PRs or otherwise modifying branches to ensure linear history, etc., all force pushes should be done with the `--force-with-lease` command line option rather than the `--force` command line option; this is for safety, and ensures that the branch on the remote has not been changed since it was last pulled.
- Pulling branches that multiple team members are working on should _always_ be done with the `--rebase` command line option (i.e., `git pull --rebase`), to prevent the creation of merge commits when other team members have squashed/cleaned up PRs.
- Branches that are merged to `main` or a release branch should be deleted on GitHub. Developers can do whatever they like with respect to already-merged branches in their own sandboxes, as long as what ends up on GitHub conforms to the rules above.
- All text files (source code, Markdown, etc.) committed to repositories in this project must use UTF-8 encoding and Mac/UNIX line endings (LF), not old Mac (CR) or Windows (CRLF) line endings, unless otherwise required by tooling. They should also be formatted such that they don't have trailing spaces on lines (in Visual Studio Code, this is easily accomplished with Ctrl-K Ctrl-X, or Command-K Command-X on macOS), and that they end with a line ending (rather than ending a line with EOF). The trailing space and newline at end of file requirements are enforced by pre-commit hooks.
- At present, we do not use Git LFS; guidelines for its use will be provided if it becomes necessary for us to use it.

### Pre-Commit Hooks

We have configured pre-commit hooks in the repository for commit message formatting, basic file formatting (whitespace at ends of lines, newline at EOF, correct formatting of YAML files), and executability of scripts with shebangs (which should be marked executable in the repository). These are managed with [the `pre-commit` tool](https://pre-commit.com/). The pre-commit hooks run as a GitHub action in CI, with the exception that the GitHub action does not check the format of commit messages; therefore, these checks are always performed, and if you commit files that violate them you will see a CI failure.

You can also install the pre-commit hooks locally, which will perform the checks locally before a commit is finalized. A nice thing about installing the hooks locally is that, if they find a problem (for instance, an extra space at the end of a line) when you try to commit, they will _fix_ that problem so that you can re-add the file in question and commit a fixed version, rather than forcing you to go fix it yourself (the exception to this is commit messages, which `pre-commit` cannot fix; you need to write them in the correct format).

To install the pre-commit hooks locally, run the following (you must have a working Python installation, likely through the use of a Python virtual environment):

```shell
pip install pre-commit
pre-commit install
```

The rest of the configuration should be automatic, and will occur the first time you make a commit.

Once we start including Rust code in the repository, we will likely add pre-commit hooks for Rust formatting; we may also do so for any other programming language we use that has a reasonable auto-formatter (e.g., Python).

## Development Environments

For developing models and documentation in the initial stages of the projects, team members can use whatever text editor/IDE they are comfortable with provided that the generated output conforms to the requirements above and works with whatever analysis tools we use for models and documentation.

We have a JupyterHub instance available at [https://freeandfair-jupyter.zapto.org](https://freeandfair-jupyter.zapto.org) for collaborative work on SysMLv2 specifications (and on Python, should any be necessary).

## External Communication

At this time, external communication about the project by team members (outside of the artifacts visible in this repository) is not allowed except as specifically authorized by the client.

## Team Communication

To the extent possible, we rely on GitHub’s features—[issues](https://github.com/FreeAndFair/TuskMobileVoting/issues), [pull requests](https://github.com/FreeAndFair/TuskMobileVoting/issues), the [project board](https://github.com/orgs/FreeAndFair/projects/2/views/2)—for ongoing discussions about specific aspects of project development, peer review of work, etc.

We use [the project Slack](https://freeandfair-e2eviv.slack.com/) as the primary mechanism for asynchronous (and lightly synchronous) team communication that does not occur through GitHub’s features. The existing project Slack channels have self-explanatory names, and should suffice for this stage of development; we can create more as necessary. Team members should assume that everything posted to a non-private Slack channel may eventually become public and conduct themselves accordingly.

We use email only in connection with GitHub (automatically-generated email from GitHub, and replies thereto to feed information back into GitHub), and for informal conversations (which can also be carried out on Slack private channels).

## Shared Documents

It is often impractical to use GitHub to actively collaborate on shared documents, though such documents, if they are project artifacts, will still end up being stored in a GitHub repository once they are complete. For such active collaboration, we use [Google Docs](https://docs.google.com/) (or other [Google Drive](https://drive.google.com) document types) for general documents, [Keynote](https://icloud.com/keynote/) for presentations, and [Overleaf](https://overleaf.com/) for LaTeX documents (e.g., [a revised version of the U.S. Vote Foundation E2E-VIV report](https://www.overleaf.com/read/bpvcrrwjbwmc#8a0af8) and the draft/shared editing version of the [coding standards](https://www.overleaf.com/read/zswcvbhxmrmd#c05626); these are read-only views of the documents).
