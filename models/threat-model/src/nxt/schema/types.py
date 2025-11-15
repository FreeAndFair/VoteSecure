# nxthreat - Type definitions
# Copyright (C) 2026 Free & Fair

"""
Type definitions for threat models.

This module provides the core types for authoring threat models:
- Properties (security objectives)
- Contexts (where attacks occur)
- Mitigations (countermeasures)
- AttackPatterns (reusable attack templates)
- Attacks (concrete attacks)
"""

from __future__ import annotations
from enum import Enum
from typing import Optional
from pydantic import BaseModel, Field


# =============================================================================
# Enumerations
# =============================================================================

class ContextKind(str, Enum):
    """The kind of context where an attack can occur."""
    SUBSYSTEM = "Subsystem"
    NETWORK = "Network"
    ACTOR = "Actor"
    PRIMITIVE = "Primitive"
    DATA = "Data"


class Scope(str, Enum):
    """
    Indicates whether a mitigation is provided by the cryptographic
    core library, partially, or not at all.
    """
    CORE = "core"
    PARTIALLY_CORE = "partially-core"
    NON_CORE = "non-core"


class EdgeType(str, Enum):
    """Types of edges in the threat model graph (internal use)."""

    # Property → Property
    REFINES = "refines"  # Child property refines parent (AND composition)

    # Attack → Property
    TARGETS = "targets"  # Attack threatens this property

    # Attack → Attack
    ACHIEVES = "achieves"  # Child attack achieves parent (OR composition)
    REQUIRES = "requires"  # Attack requires prerequisite (AND composition)
    VARIANT_OF = "variant_of"  # Concrete attack is variant of pattern

    # Attack → Context
    OCCURS_IN = "occurs_in"  # Attack occurs in this context

    # Mitigation → Attack (note: edge goes from mitigation to attack)
    MITIGATES = "mitigates"  # Mitigation addresses attack

    # For STRIDE/E-voting mappings
    MAPS_TO = "maps_to"  # External taxonomy maps to property


# =============================================================================
# Core Types
# =============================================================================

class Property(BaseModel):
    """
    A security property that the system should satisfy.

    Properties form a hierarchy with AND composition: for a property to be
    satisfied, all its children must be satisfied.

    Example:
        INTEGRITY = Property(id="INTEGRITY", description="...")
        CORRECTNESS = Property(id="CORRECTNESS", refines=INTEGRITY, description="...")
        C1 = Property(id="C1", refines=CORRECTNESS, description="Votes are cast correctly.")
    """

    id: str = Field(..., description="Unique identifier (e.g., 'C1.1', 'P1.2')")
    description: str = Field(..., description="What this property means")
    refines: Optional[Property] = Field(
        default=None,
        description="Parent property that this refines (AND composition)"
    )

    model_config = {"arbitrary_types_allowed": True}

    def __hash__(self) -> int:
        return hash(self.id)

    def __eq__(self, other: object) -> bool:
        if isinstance(other, Property):
            return self.id == other.id
        return False

    def __repr__(self) -> str:
        return f"Property({self.id!r})"


class Context(BaseModel):
    """
    A context where an attack can occur.

    Contexts represent subsystems, networks, actors, primitives, or data
    that can be the location or target of an attack.

    Example:
        BB = Context(id="BB", name="Ballot Box", kind=ContextKind.SUBSYSTEM)
        EA = Context(id="EA", name="Election Administrator", kind=ContextKind.ACTOR)
    """

    id: str = Field(..., description="Short identifier (e.g., 'BB', 'EA')")
    name: str = Field(..., description="Human-readable name")
    kind: ContextKind = Field(..., description="Category of context")
    description: Optional[str] = Field(default=None, description="Optional details")

    def __hash__(self) -> int:
        return hash(self.id)

    def __eq__(self, other: object) -> bool:
        if isinstance(other, Context):
            return self.id == other.id
        return False

    def __repr__(self) -> str:
        return f"Context({self.id!r})"


class Mitigation(BaseModel):
    """
    A countermeasure that prevents or reduces the impact of attacks.

    Mitigations are applied to attacks (or attack patterns) with a rationale
    explaining how they help.

    Example:
        message_signatures = Mitigation(
            id="M5",
            name="Message signatures",
            description="Messages on the network are digitally signed.",
            scope=Scope.CORE,
        )
    """

    id: str = Field(..., description="Unique identifier (e.g., 'M5')")
    name: str = Field(..., description="Human-readable name")
    description: str = Field(..., description="What this mitigation does")
    scope: Scope = Field(..., description="Whether provided by crypto core")

    def __hash__(self) -> int:
        return hash(self.id)

    def __eq__(self, other: object) -> bool:
        if isinstance(other, Mitigation):
            return self.id == other.id
        return False

    def __repr__(self) -> str:
        return f"Mitigation({self.id!r}, {self.name!r})"


class MitigationApplication(BaseModel):
    """
    The application of a mitigation to an attack, with a rationale.

    The rationale explains *how* this mitigation helps against this
    specific attack.

    Example:
        MitigationApplication(
            mitigation=message_signatures,
            rationale="Trustees sign messages as part of the protocol...",
        )
    """

    mitigation: Mitigation = Field(..., description="The mitigation being applied")
    rationale: str = Field(..., description="How this mitigation helps")

    model_config = {"arbitrary_types_allowed": True}


class AttackPattern(BaseModel):
    """
    An abstract attack pattern that can be instantiated as concrete attacks.

    Attack patterns (formerly "abstract attacks") define reusable attack
    templates with their own mitigations. Concrete attacks that are variants
    of a pattern inherit its mitigations.

    Example:
        compromised_device = AttackPattern(
            id="compromised_device",
            name="Compromised device",
            description="A device is altered in a way that affects security.",
        )

        malware = AttackPattern(
            id="malware",
            name="Malware",
            description="Malicious software infects the device.",
            refines=compromised_device,
            mitigations=[
                MitigationApplication(
                    mitigation=cybersecurity_malware,
                    rationale="General cybersecurity practices...",
                ),
            ],
        )
    """

    id: str = Field(..., description="Unique identifier")
    name: str = Field(..., description="Human-readable name")
    description: str = Field(..., description="What this attack pattern is")
    refines: Optional[AttackPattern] = Field(
        default=None,
        description="Parent pattern (for pattern hierarchies)"
    )
    mitigations: list[MitigationApplication] = Field(
        default_factory=list,
        description="Mitigations that apply to this pattern (inherited by variants)"
    )

    model_config = {"arbitrary_types_allowed": True}

    def __hash__(self) -> int:
        return hash(self.id)

    def __eq__(self, other: object) -> bool:
        if isinstance(other, AttackPattern):
            return self.id == other.id
        return False

    def __repr__(self) -> str:
        return f"AttackPattern({self.id!r})"


class Attack(BaseModel):
    """
    A concrete attack against the system.

    Attacks target properties, occur in contexts, and may be variants of
    attack patterns (inheriting their mitigations). Attacks can also have
    parent attacks (OR composition: any child achieving the parent suffices).

    Example:
        ballot_tampering_network_in = Attack(
            id="ballot_tampering.network_tampering.IN",
            name="Network tampering",
            description="The network adds, alters or removes cryptograms.",
            variant_of=patterns.network_tampering,
            achieves=[ballot_tampering],
            occurs_in=[contexts.IN],
            targets=[properties.C2_1],
            mitigations=[
                MitigationApplication(
                    mitigation=mitigations.recorded_as_cast,
                    rationale="The ballot tracker checking process detects...",
                ),
            ],
        )
    """

    id: str = Field(..., description="Unique identifier")
    name: str = Field(..., description="Human-readable name")
    description: Optional[str] = Field(default=None, description="What this attack does")

    # Relationships
    variant_of: Optional[AttackPattern] = Field(
        default=None,
        description="Pattern this attack instantiates (inherits mitigations)"
    )
    achieves: list[Attack] = Field(
        default_factory=list,
        description="Parent attacks this achieves (OR composition)"
    )
    requires: list[Attack] = Field(
        default_factory=list,
        description="Prerequisite attacks (AND composition)"
    )
    occurs_in: list[Context] = Field(
        default_factory=list,
        description="Contexts where this attack can occur"
    )
    targets: list[Property] = Field(
        default_factory=list,
        description="Properties this attack threatens"
    )

    # Direct mitigations (in addition to inherited ones)
    mitigations: list[MitigationApplication] = Field(
        default_factory=list,
        description="Mitigations applied directly to this attack"
    )

    model_config = {"arbitrary_types_allowed": True}

    def __hash__(self) -> int:
        return hash(self.id)

    def __eq__(self, other: object) -> bool:
        if isinstance(other, Attack):
            return self.id == other.id
        return False

    def __repr__(self) -> str:
        return f"Attack({self.id!r})"


# =============================================================================
# Special instances
# =============================================================================

OUT_OF_SCOPE = Mitigation(
    id="OOS",
    name="Out of scope",
    description="This attack cannot be mitigated within the system scope.",
    scope=Scope.NON_CORE,
)
