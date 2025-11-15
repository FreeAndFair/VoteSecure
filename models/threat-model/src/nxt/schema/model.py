# nxt - Threat Model container
# Copyright (C) 2026 Free & Fair

"""
The ThreatModel class collects all types and builds the NetworkX graph.
"""

from __future__ import annotations
from typing import Iterator
from pydantic import BaseModel, Field
import networkx as nx

from .types import EdgeType, Property, Context, Mitigation, AttackPattern, Attack, MitigationApplication


class ThreatModel(BaseModel):
    """
    Container for a complete threat model.

    Collects all properties, contexts, mitigations, attack patterns, and
    attacks, then builds a NetworkX graph for querying.

    Example:
        model = ThreatModel(
            name="E2E-VIV Threat Model",
            properties=[CONFIDENTIALITY, INTEGRITY, ...],
            contexts=[BB, EA, IN, ...],
            mitigations=[message_signatures, ...],
            patterns=[compromised_device, network_tampering, ...],
            attacks=[ballot_tampering_network_in, ...],
        )

        # Query the model
        outstanding = model.get_outstanding_attacks()
        mits = model.get_mitigations_for(some_attack)
    """

    name: str = Field(..., description="Name of this threat model")
    description: str = Field(default="", description="Description of what this models")

    properties: list[Property] = Field(default_factory=list)
    contexts: list[Context] = Field(default_factory=list)
    mitigations: list[Mitigation] = Field(default_factory=list)
    patterns: list[AttackPattern] = Field(default_factory=list)
    attacks: list[Attack] = Field(default_factory=list)

    model_config = {"arbitrary_types_allowed": True}

    _graph: nx.DiGraph | None = None

    def build(self) -> nx.DiGraph:
        """
        Build and return the NetworkX graph representation.

        The graph is cached; subsequent calls return the same graph.
        Call rebuild() to force reconstruction.
        """
        if self._graph is not None:
            return self._graph

        G = nx.DiGraph()

        # Add all nodes with their type as an attribute
        for prop in self.properties:
            G.add_node(prop.id, node=prop, node_type="property")

        for ctx in self.contexts:
            G.add_node(ctx.id, node=ctx, node_type="context")

        for mit in self.mitigations:
            G.add_node(mit.id, node=mit, node_type="mitigation")

        for pattern in self.patterns:
            G.add_node(pattern.id, node=pattern, node_type="pattern")

        for attack in self.attacks:
            G.add_node(attack.id, node=attack, node_type="attack")

        # Add edges for properties
        for prop in self.properties:
            if prop.refines:
                G.add_edge(prop.id, prop.refines.id, edge_type=EdgeType.REFINES)

        # Add edges for attack patterns
        for pattern in self.patterns:
            if pattern.refines:
                G.add_edge(pattern.id, pattern.refines.id, edge_type=EdgeType.REFINES)
            for ma in pattern.mitigations:
                G.add_edge(
                    ma.mitigation.id, pattern.id,
                    edge_type=EdgeType.MITIGATES,
                    rationale=ma.rationale
                )

        # Add edges for attacks
        for attack in self.attacks:
            # variant_of
            if attack.variant_of:
                G.add_edge(attack.id, attack.variant_of.id, edge_type=EdgeType.VARIANT_OF)

            # achieves (parent attacks)
            for parent in attack.achieves:
                G.add_edge(attack.id, parent.id, edge_type=EdgeType.ACHIEVES)

            # requires (prerequisites)
            for prereq in attack.requires:
                G.add_edge(attack.id, prereq.id, edge_type=EdgeType.REQUIRES)

            # occurs_in
            for ctx in attack.occurs_in:
                G.add_edge(attack.id, ctx.id, edge_type=EdgeType.OCCURS_IN)

            # targets
            for prop in attack.targets:
                G.add_edge(attack.id, prop.id, edge_type=EdgeType.TARGETS)

            # direct mitigations
            for ma in attack.mitigations:
                G.add_edge(
                    ma.mitigation.id, attack.id,
                    edge_type=EdgeType.MITIGATES,
                    rationale=ma.rationale
                )

        self._graph = G
        return G

    def rebuild(self) -> nx.DiGraph:
        """Force rebuild of the graph."""
        self._graph = None
        return self.build()

    @property
    def graph(self) -> nx.DiGraph:
        """The NetworkX graph (built on first access)."""
        return self.build()

    # =========================================================================
    # Query methods
    # =========================================================================

    def get_mitigations_for(self, attack: Attack, include_inherited: bool = True) -> list[tuple[Mitigation, str]]:
        """
        Get all mitigations for an attack.

        Args:
            attack: The attack to get mitigations for
            include_inherited: If True, include mitigations from variant_of patterns

        Returns:
            List of (Mitigation, rationale) tuples
        """
        G = self.graph
        result: list[tuple[Mitigation, str]] = []

        # Direct mitigations on this attack
        for ma in attack.mitigations:
            result.append((ma.mitigation, ma.rationale))

        # Inherited mitigations via variant_of
        if include_inherited and attack.variant_of:
            result.extend(self._get_pattern_mitigations(attack.variant_of))

        return result

    def _get_pattern_mitigations(self, pattern: AttackPattern) -> list[tuple[Mitigation, str]]:
        """
        Collect mitigations from a pattern and all its descendants.

        In the legacy model, when an attack is instance_of a pattern, it inherits
        mitigations from ALL children of that pattern. For example, an attack that
        is instance_of 'Compromised device' inherits mitigations from Malware,
        Intrusion, Escalation, etc. (all children of Compromised device).
        """
        result: list[tuple[Mitigation, str]] = []

        # Mitigations on this pattern
        for ma in pattern.mitigations:
            result.append((ma.mitigation, ma.rationale))

        # Mitigations from all child patterns (patterns that refine this one)
        for child_pattern in self.patterns:
            if child_pattern.refines and child_pattern.refines.id == pattern.id:
                result.extend(self._get_pattern_mitigations(child_pattern))

        return result

    def get_outstanding_attacks(self) -> list[Attack]:
        """
        Get attacks that have no mitigations (direct or inherited).

        An attack is outstanding if:
        - It has no direct mitigations
        - It has no variant_of, or its variant_of chain has no mitigations
        - It has no children (attacks that achieve it)
        """
        G = self.graph
        outstanding = []

        for attack in self.attacks:
            mitigations = self.get_mitigations_for(attack)
            if not mitigations:
                # Check if it has children that might have mitigations
                children = [
                    a for a in self.attacks
                    if attack in a.achieves
                ]
                if not children:
                    outstanding.append(attack)

        return outstanding

    def get_attacks_targeting(self, prop: Property) -> list[Attack]:
        """Get all attacks that target a property (directly or via refinement)."""
        G = self.graph
        result = []

        # Collect this property and all properties that refine it
        prop_ids = {prop.id}
        for p in self.properties:
            if self._refines_property(p, prop):
                prop_ids.add(p.id)

        # Find attacks targeting any of these properties
        for attack in self.attacks:
            for target in attack.targets:
                if target.id in prop_ids:
                    result.append(attack)
                    break

        return result

    def _refines_property(self, child: Property, ancestor: Property) -> bool:
        """Check if child transitively refines ancestor."""
        current = child.refines
        while current:
            if current.id == ancestor.id:
                return True
            current = current.refines
        return False

    def get_attacks_in_context(self, ctx: Context) -> list[Attack]:
        """Get all attacks that occur in a given context."""
        return [a for a in self.attacks if ctx in a.occurs_in]

    def get_property_tree(self, root: Property | None = None) -> list[Property]:
        """
        Get properties in tree order.

        Args:
            root: If provided, only return properties under this root

        Returns:
            Properties in depth-first order
        """
        if root is None:
            roots = [p for p in self.properties if p.refines is None]
        else:
            roots = [root]

        result = []
        for r in roots:
            self._collect_property_tree(r, result)
        return result

    def _collect_property_tree(self, prop: Property, result: list[Property]) -> None:
        result.append(prop)
        children = [p for p in self.properties if p.refines and p.refines.id == prop.id]
        for child in sorted(children, key=lambda p: p.id):
            self._collect_property_tree(child, result)

    def get_attack_tree(self, root: Attack | None = None) -> list[Attack]:
        """
        Get attacks in tree order (following achieves relationships).

        Args:
            root: If provided, only return attacks under this root

        Returns:
            Attacks in depth-first order
        """
        if root is None:
            # Roots are attacks with no achieves
            roots = [a for a in self.attacks if not a.achieves]
        else:
            roots = [root]

        result = []
        for r in roots:
            self._collect_attack_tree(r, result)
        return result

    def _collect_attack_tree(self, attack: Attack, result: list[Attack]) -> None:
        result.append(attack)
        children = [a for a in self.attacks if attack in a.achieves]
        for child in sorted(children, key=lambda a: a.id):
            self._collect_attack_tree(child, result)
