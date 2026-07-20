#!/usr/bin/env bash
#
# Reject a push if any commit being pushed lacks a signature.
#
# Signed commits are mandatory for this repository (see CONTRIBUTING.md).
# Server-side branch protection enforces cryptographic *validity*; this hook is
# the fast local guard that catches the common failure mode -- a commit created
# with signing disabled (e.g. a tool or agent passing `--no-gpg-sign`, or
# `commit.gpgsign` left unset) -- before it ever leaves your machine.
#
# Wired in as a pre-commit-framework `pre-push` hook (see .pre-commit-config.yaml).
# pre-commit provides the refs being pushed via PRE_COMMIT_FROM_REF /
# PRE_COMMIT_TO_REF; we fall back to the current branch's upstream when run
# outside that framework.

set -euo pipefail

ZERO='0000000000000000000000000000000000000000'

from="${PRE_COMMIT_FROM_REF:-}"
to="${PRE_COMMIT_TO_REF:-}"

# Determine the set of commits about to be pushed.
if [ -n "$to" ]; then
    if [ "$to" = "$ZERO" ]; then
        exit 0  # branch deletion: nothing to inspect
    fi
    if [ -z "$from" ] || [ "$from" = "$ZERO" ]; then
        # New branch on the remote: inspect commits not already published.
        range=$(git rev-list "$to" --not --remotes)
    else
        range=$(git rev-list "${from}..${to}")
    fi
elif upstream=$(git rev-parse --abbrev-ref --symbolic-full-name '@{u}' 2>/dev/null); then
    range=$(git rev-list "${upstream}..HEAD")
else
    range=$(git rev-list HEAD --not --remotes)
fi

[ -z "$range" ] && exit 0

# %G? reports the signature state: N = no signature. Anything else (G, U, X,
# Y, R, E) means a signature is present; server-side verification judges its
# validity and trust.
unsigned=""
while IFS= read -r sha; do
    [ -z "$sha" ] && continue
    if [ "$(git log -1 --format='%G?' "$sha")" = "N" ]; then
        unsigned+="  $(git log -1 --format='%h %s' "$sha")"$'\n'
    fi
done <<< "$range"

if [ -n "$unsigned" ]; then
    {
        echo "✖ Push rejected: the following commits are not signed:"
        echo
        printf '%s' "$unsigned"
        echo
        echo "This repository requires signed commits. Re-sign them before pushing:"
        echo
        echo "    git rebase --exec 'git commit --amend --no-edit -S --no-verify' <base>"
        echo
        echo "and make sure signing stays on (commit.gpgsign=true) and that no tool"
        echo "or agent is passing --no-gpg-sign."
    } >&2
    exit 1
fi

exit 0
