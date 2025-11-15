# SecureVote Threat Model - Legacy Compatibility Layer
#
# This module provides data structures compatible with the legacy
# read_database.py format, enabling drop-in replacement for the
# web server and PDF rendering applications.

from typing import Any
from natsort import natsorted
from nxt import ThreatModel, Property, Attack, Context, Mitigation, AttackPattern


def build_data_structures(
    model: ThreatModel,
    patterns: list[AttackPattern] | None = None
) -> tuple[dict, dict, dict, dict]:
    """
    Build native Python data structures from the threat model,
    matching the format returned by legacy read_database.py.

    Args:
        model: The threat model to convert
        patterns: List of attack patterns (abstract attacks). If None,
            patterns are discovered by collecting variant_of references.

    Returns:
        Tuple of (property_dict, context_dict, mitigation_dict, attack_dict)
        where each dict is keyed by synthetic integer IDs.
    """
    # Collect all attack patterns
    if patterns is None:
        # Discover patterns from variant_of references
        pattern_set: set[AttackPattern] = set()
        for attack in model.attacks:
            if attack.variant_of:
                pattern_set.add(attack.variant_of)
        patterns = list(pattern_set)

    # Build ID mappings (synthetic database IDs)
    property_id_map: dict[Property, int] = {}
    context_id_map: dict[Context, int] = {}
    mitigation_id_map: dict[Mitigation, int] = {}
    attack_id_map: dict[Attack | AttackPattern, int] = {}

    # Assign IDs
    for i, prop in enumerate(model.properties, start=1):
        property_id_map[prop] = i

    for i, ctx in enumerate(model.contexts, start=1):
        context_id_map[ctx] = i

    for i, mit in enumerate(model.mitigations, start=1):
        mitigation_id_map[mit] = i

    # Attacks: patterns first (abstract), then concrete attacks
    all_attacks = list(patterns) + list(model.attacks)
    for i, atk in enumerate(all_attacks, start=1):
        attack_id_map[atk] = i

    # Build property dictionary
    property_dict = _build_property_dict(model, property_id_map, attack_id_map)

    # Build context dictionary
    context_dict = _build_context_dict(model, context_id_map)

    # Build mitigation dictionary
    mitigation_dict = _build_mitigation_dict(model, mitigation_id_map, attack_id_map)

    # Build attack dictionary
    attack_dict = _build_attack_dict(
        model, patterns, attack_id_map, property_id_map,
        mitigation_id_map, context_id_map, property_dict,
        context_dict, mitigation_dict
    )

    # Generate auto-identifiers (modifies dicts in place)
    attack_roots = [a for a in attack_dict.values() if not a['parents']]
    _gen_attack_ids(attack_roots)

    property_roots = [p for p in property_dict.values() if p['parent'] is None]
    _gen_property_ids(property_roots, top=True)

    _gen_context_ids(list(context_dict.values()), 'CX')

    _gen_mitigation_ids(list(mitigation_dict.values()), 'M')

    return property_dict, context_dict, mitigation_dict, attack_dict


def get_legacy_data() -> tuple[dict, dict, dict, dict]:
    """
    Convenience function that returns threat model data in legacy format.

    This is a drop-in replacement for:
        from read_database import build_data_structures
        property_dict, context_dict, mitigation_dict, attack_dict = build_data_structures(db_file_path)

    Usage:
        from nxt.model.compat import get_legacy_data
        property_dict, context_dict, mitigation_dict, attack_dict = get_legacy_data()

    Returns:
        Tuple of (property_dict, context_dict, mitigation_dict, attack_dict)
    """
    from . import model, patterns
    return build_data_structures(model, patterns.ALL)


def _build_property_dict(
    model: ThreatModel,
    property_id_map: dict[Property, int],
    attack_id_map: dict[Attack | AttackPattern, int]
) -> dict[int, dict]:
    """Build property dictionary in legacy format."""
    property_dict = {}

    for prop in model.properties:
        prop_id = property_id_map[prop]
        property_dict[prop_id] = {
            'id': prop_id,
            'name': prop.id,  # In legacy, 'name' is the identifier like 'CONFIDENTIALITY'
            'description': prop.description,
            'kind': 'Model',  # All our properties are Model kind
            'identifier': prop.id,
            'parent': None,  # Will be linked below
            'children': [],  # Will be populated below
            'related_properties': [],  # Not used in our model currently
            'attacks': [],  # Will be populated when building attacks
        }

    # Link parent-child relationships
    for prop in model.properties:
        prop_id = property_id_map[prop]
        if prop.refines:
            parent_id = property_id_map[prop.refines]
            property_dict[prop_id]['parent'] = property_dict[parent_id]
            property_dict[parent_id]['children'].append(property_dict[prop_id])

    return property_dict


def _build_context_dict(
    model: ThreatModel,
    context_id_map: dict[Context, int]
) -> dict[int, dict]:
    """Build context dictionary in legacy format."""
    context_dict = {}

    for ctx in model.contexts:
        ctx_id = context_id_map[ctx]
        # Convert enum to string for legacy compatibility
        kind_str = ctx.kind.value if hasattr(ctx.kind, 'value') else str(ctx.kind)
        context_dict[ctx_id] = {
            'id': ctx_id,
            'name': ctx.name,
            'kind': kind_str,
            'description': ctx.description if hasattr(ctx, 'description') else None,
            'identifier': ctx.id,
        }

    return context_dict


def _build_mitigation_dict(
    model: ThreatModel,
    mitigation_id_map: dict[Mitigation, int],
    attack_id_map: dict[Attack | AttackPattern, int]
) -> dict[int, dict]:
    """Build mitigation dictionary in legacy format.

    Note: 'Out of scope' is excluded - in legacy, this is represented as
    NULL mitigation_fk entries in the attack_mitigation join table.
    """
    mitigation_dict = {}

    for mit in model.mitigations:
        # LEGACY COMPAT: Skip "Out of scope" - it's not a real mitigation in legacy
        if mit.name == "Out of scope":
            continue

        mit_id = mitigation_id_map[mit]
        # Convert enum to string for legacy compatibility
        scope_str = mit.scope.value if hasattr(mit.scope, 'value') else str(mit.scope)
        mitigation_dict[mit_id] = {
            'id': mit_id,
            'name': mit.name,
            'description': mit.description,
            'identifier': mit.id,
            'scope': scope_str,
            'attacks': [],  # Will be populated when building attacks
        }

    return mitigation_dict


def _build_attack_dict(
    model: ThreatModel,
    patterns: set[AttackPattern],
    attack_id_map: dict[Attack | AttackPattern, int],
    property_id_map: dict[Property, int],
    mitigation_id_map: dict[Mitigation, int],
    context_id_map: dict[Context, int],
    property_dict: dict[int, dict],
    context_dict: dict[int, dict],
    mitigation_dict: dict[int, dict]
) -> dict[int, dict]:
    """Build attack dictionary in legacy format."""
    attack_dict = {}

    # First pass: create all attack entries
    # Patterns (abstract attacks)
    for pattern in patterns:
        atk_id = attack_id_map[pattern]
        attack_dict[atk_id] = {
            'id': atk_id,
            'identifier': pattern.name,
            'name': pattern.name,
            'description': pattern.description if hasattr(pattern, 'description') else '',
            'is_abstract': 1,
            'instance_of': None,
            'context': None,
            'likelihood': None,
            'impact': None,
            'properties': [],
            'mitigations': [],
            'children': [],
            'parents': [],
        }

        # Add mitigations for patterns
        if hasattr(pattern, 'mitigations') and pattern.mitigations:
            for ma in pattern.mitigations:
                # LEGACY COMPAT: "Out of scope" is represented as NULL mitigation
                if ma.mitigation.name == "Out of scope":
                    attack_dict[atk_id]['mitigations'].append({
                        'mitigation': None,
                        'rationale': ma.rationale
                    })
                else:
                    mit_id = mitigation_id_map.get(ma.mitigation)
                    if mit_id:
                        attack_dict[atk_id]['mitigations'].append({
                            'mitigation': mitigation_dict[mit_id],
                            'rationale': ma.rationale
                        })
                        mitigation_dict[mit_id]['attacks'].append(attack_dict[atk_id])

    # Concrete attacks
    for attack in model.attacks:
        atk_id = attack_id_map[attack]

        # Get context (legacy only supports single context)
        ctx = None
        if attack.occurs_in:
            ctx_id = context_id_map.get(attack.occurs_in[0])
            ctx = context_dict.get(ctx_id) if ctx_id else None

        # Get instance_of (variant_of in our model)
        instance_of = None
        if attack.variant_of:
            instance_of_id = attack_id_map.get(attack.variant_of)
            # Will link after all attacks are created

        # LEGACY COMPAT: Build qualified identifier
        # Format: Parent.Name.Context (e.g., "Bad mixing.Corruption.EA")
        # For attacks without parents, just use the name
        identifier_parts = [attack.name]
        if attack.achieves:
            # Use first parent's name as prefix
            parent_name = attack.achieves[0].name
            identifier_parts.insert(0, parent_name)
        if attack.occurs_in:
            # Add context suffix
            ctx_ids = ','.join(c.id for c in attack.occurs_in)
            identifier_parts.append(ctx_ids)
        qualified_identifier = '.'.join(identifier_parts)

        attack_dict[atk_id] = {
            'id': atk_id,
            'identifier': qualified_identifier,
            'name': attack.name,
            'description': attack.description if hasattr(attack, 'description') else '',
            'is_abstract': 0,
            'instance_of': None,  # Will be linked below
            'context': ctx,
            'likelihood': None,
            'impact': None,
            'properties': [],
            'mitigations': [],
            'children': [],
            'parents': [],
        }

        # Add properties
        if attack.targets:
            for prop in attack.targets:
                prop_id = property_id_map.get(prop)
                if prop_id:
                    attack_dict[atk_id]['properties'].append(property_dict[prop_id])
                    property_dict[prop_id]['attacks'].append(attack_dict[atk_id])

        # Add mitigations
        if attack.mitigations:
            for ma in attack.mitigations:
                # LEGACY COMPAT: "Out of scope" is represented as NULL mitigation
                if ma.mitigation.name == "Out of scope":
                    attack_dict[atk_id]['mitigations'].append({
                        'mitigation': None,
                        'rationale': ma.rationale
                    })
                else:
                    mit_id = mitigation_id_map.get(ma.mitigation)
                    if mit_id:
                        attack_dict[atk_id]['mitigations'].append({
                            'mitigation': mitigation_dict[mit_id],
                            'rationale': ma.rationale
                        })
                        mitigation_dict[mit_id]['attacks'].append(attack_dict[atk_id])

    # Second pass: link relationships
    for attack in model.attacks:
        atk_id = attack_id_map[attack]

        # Link instance_of (variant_of)
        if attack.variant_of:
            instance_of_id = attack_id_map.get(attack.variant_of)
            if instance_of_id:
                attack_dict[atk_id]['instance_of'] = attack_dict[instance_of_id]

        # Link parent-child (achieves in our model = parents in legacy)
        if attack.achieves:
            for parent in attack.achieves:
                parent_id = attack_id_map.get(parent)
                if parent_id:
                    attack_dict[atk_id]['parents'].append(attack_dict[parent_id])
                    attack_dict[parent_id]['children'].append(attack_dict[atk_id])

    # Third pass: link pattern parent-child relationships (using refines)
    for pattern in patterns:
        if hasattr(pattern, 'refines') and pattern.refines:
            pattern_id = attack_id_map.get(pattern)
            parent_id = attack_id_map.get(pattern.refines)
            if pattern_id and parent_id:
                attack_dict[pattern_id]['parents'].append(attack_dict[parent_id])
                attack_dict[parent_id]['children'].append(attack_dict[pattern_id])

    return attack_dict


# Auto-identifier generation (matching legacy read_database.py)

PROPERTY_PREFIX = {
    "CONFIDENTIALITY": "P",
    "CORRECTNESS": "C",
    "VERIFIABILITY": "V",
    "DISPUTE_FREENESS": "D",
    "AVAILABILITY": "A"
}


def _get_property_prefix(identifier: str) -> str | None:
    """Determine the prefix for certain special top-level properties."""
    return PROPERTY_PREFIX.get(identifier)


def _gen_attack_ids(roots: list[dict], prefix: str | None = None) -> None:
    """Autogenerate and set attack identifiers."""
    roots = natsorted(roots, key=lambda value: value['identifier'])

    index = 1
    abs_index = 1

    for root in roots:
        if root['is_abstract']:
            effective_index = abs_index
            abs_index += 1
        else:
            effective_index = index
            index += 1

        if prefix is None:
            attack_prefix = 'AATK' if root['is_abstract'] == 1 else 'ATK'
            root['auto_identifier'] = f"{attack_prefix}{effective_index}"
        else:
            root['auto_identifier'] = f"{prefix}.{effective_index}"

        if root['children']:
            _gen_attack_ids(root['children'], root['auto_identifier'])


def _gen_property_ids(roots: list[dict], prefix: str | None = None, top: bool = False) -> None:
    """Autogenerate and set property identifiers."""
    roots = natsorted(roots, key=lambda value: value['identifier'])

    for index, root in enumerate(roots):
        identifier = root['identifier']

        property_prefix = None
        if prefix is None and root['kind'] == 'Model':
            property_prefix = _get_property_prefix(identifier)

        if property_prefix is None or top:
            root['auto_identifier'] = identifier
        else:
            root['auto_identifier'] = f"{property_prefix}.{(index + 1)}"

        if root['children']:
            _gen_property_ids(root['children'], root['auto_identifier'])


def _gen_context_ids(ctxs: list[dict], prefix: str) -> None:
    """Autogenerate and set context identifiers."""
    ctxs = natsorted(ctxs, key=lambda value: value['name'])

    for index, ctx in enumerate(ctxs):
        ctx['auto_identifier'] = f"{prefix}{(index + 1)}"


def _gen_mitigation_ids(mitigations: list[dict], prefix: str) -> None:
    """Autogenerate and set mitigation identifiers."""
    mitigations = natsorted(mitigations, key=lambda value: value['name'])

    for index, mit in enumerate(mitigations):
        mit['auto_identifier'] = f"{prefix}{(index + 1)}"
