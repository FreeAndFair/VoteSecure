# nxt - Threat Modeling with NetworkX
# Copyright (C) 2026 Free & Fair

"""
Threat modeling for SecureVote.

The authoring layer provides Pydantic models with IDE support
(autocomplete, type checking, refactoring). These are converted to
a NetworkX graph for querying and analysis.
"""

from .schema import (
    # Node types
    Property,
    Attack,
    AttackPattern,
    Mitigation,
    Context,
    OUT_OF_SCOPE,
    # Supporting types
    ContextKind,
    Scope,
    MitigationApplication,
    # Model container
    ThreatModel,
)

__all__ = [
    "Property",
    "Attack",
    "AttackPattern",
    "Mitigation",
    "Context",
    "OUT_OF_SCOPE",
    "ContextKind",
    "Scope",
    "MitigationApplication",
    "ThreatModel",
]

__version__ = "0.1.0"
