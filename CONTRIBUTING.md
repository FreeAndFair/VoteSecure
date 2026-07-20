# Contributing

We welcome contributions to this repository; when contributing changes to artifacts, please discuss the changes via GitHub issue, email to the project maintainers, or other method of communication before doing so. Note that this project has a [code of conduct](CODE_OF_CONDUCT.md), which you should follow in all your interactions with the repository and the project team.

## Issues and Feature Requests

If you find a bug in the code or a mistake in our documentation or other artifacts, or you'd like to see a new feature, you can help us by [submitting an issue on GitHub](https://github.com/FreeAndFair/VoteSecure/issues). Before you create an issue, please search the issue archive; it's possible that your issue has already been addressed, or is in the process of being addressed.

If the issue you've found has to do with security, please **do not file a public GitHub issue**. See [our documentation on reporting security issues](./SECURITY.md) for details.

If you file a GitHub issue, please try to make it:

- *Reproducible*. Include steps to reproduce the problem (if applicable).
- *Specific*. Include as much detail as possible; what version/repository revision, what environment are you running in, etc.
- *Unique*. Do not duplicate existing GitHub issues.
- *Scoped to a Single Problem*. One problem or feature request per GitHub issue.

If you have a concrete suggestion for addressing an issue (e.g., you've already written a patch), you can submit a pull request.

### How to Submit a Pull Request

1. Search the existing (open and closed) [pull requests](https://github.com/FreeAndFair/VoteSecure/pulls) that relate to your submission, so that you don't duplicate effort.
2. Create a fork of the project.
3. Create a feature branch for your pull request (`git checkout -b feat/my_new_feature`).
4. Commit your changes to that branch. This project follows the [Conventional Commits](https://www.conventionalcommits.org/) standard, so you should do the same in your commit messages. **Every commit must be cryptographically signed** (see [Signed Commits](#signed-commits) below).
5. Push your changes to that branch.
6. [Open a pull request](https://github.com/FreeAndFair/VoteSecure/compare?expand=1)

## Signed Commits

**All commits to this repository must be signed.** This is not optional: our
`main` branch is protected server-side and will reject any push containing an
unsigned commit.

To avoid discovering this only at push time, we also ship a local guard. After
cloning, install the `pre-push` hook once:

```
pre-commit install --hook-type pre-push
```

That wires in a check (`utils/git/require-signed-commits.sh`) that rejects a
push if any outgoing commit lacks a signature.

To sign automatically, turn signing on globally and configure a signing key:

```
git config --global commit.gpgsign true
git config --global user.signingkey <your-key>
```

The most common way commits end up unsigned despite this setting is a per-command
override: `git commit --no-gpg-sign`, or a tool invoking `git -c commit.gpgsign=false`.
**Do not** disable signing for convenience. If a headless or agent environment
cannot reach your signing key, fix the environment (e.g. cache the passphrase in
the agent, set `GPG_TTY`) rather than turning signing off.

If you have already made unsigned commits on a branch, re-sign them before
pushing:

```
git rebase --exec 'git commit --amend --no-edit -S --no-verify' <base>
```

## Documenting AI Tool Use

We use AI coding assistants — agents and the models behind them — in this
project, and we document that use openly. Two principles govern how:

- **We do not hide it.** When a model materially generates or revises content
  (code, prose, models, specifications), that is recorded on the commit.
- **We do not attribute authorship to a tool.** A model cannot be responsible
  for a change, so it does not receive authorship credit — no more than a spell
  checker or an editor does.

Concretely:

- **Do not** use a `Co-authored-by:` trailer (or any `Name <email>` trailer) for
  an AI tool. Presentation layers such as GitHub parse those as human
  contributors and fold them into contribution statistics, crediting an entity
  that cannot bear responsibility.
- **Do** record the tools with an `AI-Tools-Used:` trailer at the end of the
  commit message. Itemize the coding agent(s) and model(s) that materially
  contributed to the change:

  ```
  AI-Tools-Used: Claude Code (Claude Opus 4.8, 1M context)
  ```

  List multiple tools separated by `;`:

  ```
  AI-Tools-Used: Claude Code (Claude Opus 4.8); GitHub Copilot
  ```

Notes:

- **AI coding agents must not disable commit signing.** Signed commits are
  mandatory (see [Signed Commits](#signed-commits)); an agent or automation
  acting on a contributor's behalf must never pass `--no-gpg-sign` or
  `-c commit.gpgsign=false` to work around a signing prompt. Configure the
  environment so the agent can sign as the contributor instead.
- Some tools hide the specific model — e.g. GitHub Copilot's "Auto" mode does
  not disclose which model served a request; it can only be recovered from
  enterprise logs. Record what you can identify, and consult those logs when
  precision matters.
- GitHub-generated merge commits re-append the `Co-authored-by:` suffix we
  avoid. Trim it before merging, or prefer a linear history that does not rely
  on GitHub-generated merge commits.
