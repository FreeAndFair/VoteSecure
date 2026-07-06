#!/usr/bin/env python3
"""
Tamarin oracle for VoteSecure subprotocols.
Copyright (C) 2026 Free & Fair.

Priority order (lower number = solved first):

  0 - BB_Advance action facts
      → commits which BB_Current tip was consumed by each append, collapsing
        case-splits before the BB_Append_Request fan-out can multiply

  1 - BB_Trace_Entry action facts
      → grounds entry content after the chain structure is committed

  2 - !BB_Root premise goals
      → unifies symbolic ~bbid variables early

  3 - !BB_Entry and BB_Append_Request premise goals
      → resolves entry content and append requests once the board is known

  4 - BB_Current and BB_Create_Request premise goals
      → resolves which BB tip is needed / board initialisation

  5 - BallotStyle_Trace and EligibleVoter_Trace action facts
      → grounds the N=1/N=2 search-space bound variables early

  6 - VA_State_* and !VA_Eligible_Voter goals
      → voter session state and eligibility

  7 - SecureReceive goals
      → secure channel receipt

  8 - Everything else (KU goals, ordering constraints, etc.)
"""
import sys

lines = sys.stdin.read().splitlines()

goals = []
for line in lines:
    if ':' not in line:
        continue
    idx_str, formula = line.split(':', 1)
    try:
        idx = int(idx_str.strip())
    except ValueError:
        continue
    goals.append((idx, formula.strip()))


def priority(goal):
    _, f = goal

    # BB_Advance action facts — commit BB append events before fan-out
    if 'BB_Advance(' in f and '@ #' in f and '▶' not in f:
        return 0

    # BB_Trace_Entry action facts
    if 'BB_Trace_Entry(' in f and '@ #' in f and '▶' not in f:
        return 1

    # !BB_Root premise goals — unify ~bbid early
    if '!BB_Root(' in f:
        return 2

    # !BB_Entry and BB_Append_Request premise goals
    if '!BB_Entry(' in f or 'BB_Append_Request(' in f:
        return 3

    # BB_Current and BB_Create_Request premise goals
    if 'BB_Current(' in f or 'BB_Create_Request(' in f:
        return 4

    # Search-space bound grounding atoms
    if 'BallotStyle_Trace(' in f or 'EligibleVoter_Trace(' in f:
        return 5

    # Voter session state and eligibility
    if 'VA_State_' in f or '!VA_Eligible_Voter(' in f:
        return 6

    # Secure channel receipt
    if 'SecureReceive(' in f:
        return 7

    # Everything else
    return 8


goals.sort(key=priority)
for idx, _ in goals:
    print(idx)
