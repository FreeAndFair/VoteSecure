# SecureVote Threat Model - View Functions
# Replicating legacy view.py queries using NetworkX

from typing import Optional
from nxt import ThreatModel, Property, Attack, AttackPattern, Context, Mitigation


def property_tree(model: ThreatModel, root: Optional[Property] = None) -> str:
    """
    Display property tree in legacy format.

    Legacy format:
        AVAILABILITY The e-voting properties of {Robustness}...
        ├── A1 Every voter must be able to cast...
        ├── A2 All participants must be able to...
    """
    lines = []

    # Get tree order
    if root is None:
        roots = [p for p in model.properties if p.refines is None]
    else:
        roots = [root]

    for r in sorted(roots, key=lambda p: p.id):
        _render_property_tree(model, r, lines, prefix="", is_last=True, is_root=True)

    return "\n".join(lines)


def _render_property_tree(
    model: ThreatModel,
    prop: Property,
    lines: list[str],
    prefix: str,
    is_last: bool,
    is_root: bool
) -> None:
    """Recursively render property tree with box-drawing characters."""
    # Truncate description to ~50 chars for display
    desc = prop.description[:50] + ".." if len(prop.description) > 50 else prop.description

    if is_root:
        lines.append(f"{prop.id} {desc}")
        child_prefix = ""
    else:
        connector = "└── " if is_last else "├── "
        lines.append(f"{prefix}{connector}{prop.id} {desc}")
        child_prefix = prefix + ("    " if is_last else "│   ")

    # Get children sorted by ID
    children = sorted(
        [p for p in model.properties if p.refines and p.refines.id == prop.id],
        key=lambda p: p.id
    )

    for i, child in enumerate(children):
        _render_property_tree(
            model, child, lines, child_prefix,
            is_last=(i == len(children) - 1),
            is_root=False
        )


def attack_tree(model: ThreatModel, root: Optional[Attack] = None) -> str:
    """
    Display attack tree in legacy format.

    Legacy format:
        Bad decryption
        ├─Compromised device (TA)
        ├─Corruption (TR)
    """
    lines = []

    if root is None:
        # Roots are attacks with no achieves and no requires
        roots = [a for a in model.attacks if not a.achieves and not a.requires]
    else:
        roots = [root]

    for r in sorted(roots, key=lambda a: a.name):
        _render_attack_tree(model, r, lines, prefix="", is_last=True, is_root=True)

    return "\n".join(lines)


def _render_attack_tree(
    model: ThreatModel,
    attack: Attack,
    lines: list[str],
    prefix: str,
    is_last: bool,
    is_root: bool
) -> None:
    """Recursively render attack tree with context annotation."""
    # Format: name (context) for leaf attacks
    ctx_str = ""
    if attack.occurs_in:
        ctx_str = f" ({', '.join(c.id for c in attack.occurs_in)})"

    name = attack.name

    if is_root:
        lines.append(f"{name}")
        child_prefix = ""
    else:
        connector = "└── " if is_last else "├── "
        lines.append(f"{prefix}{connector}{name}{ctx_str}")
        child_prefix = prefix + ("    " if is_last else "│   ")

    # Get children (attacks that achieve or require this one)
    children = sorted(
        [a for a in model.attacks if attack in a.achieves or attack in a.requires],
        key=lambda a: a.name
    )

    for i, child in enumerate(children):
        _render_attack_tree(
            model, child, lines, child_prefix,
            is_last=(i == len(children) - 1),
            is_root=False
        )


def context_table(model: ThreatModel) -> str:
    """Display contexts in table format."""
    lines = [
        "+------------------------------------+-----------+---------------+",
        "| Name                               | Kind      | Description   |",
        "+====================================+===========+===============+",
    ]

    for ctx in sorted(model.contexts, key=lambda c: c.name):
        name = ctx.name[:34].ljust(34)
        kind = ctx.kind.value[:9].ljust(9)
        desc = (ctx.description or "")[:13].ljust(13)
        lines.append(f"| {name} | {kind} | {desc} |")
        lines.append("+------------------------------------+-----------+---------------+")

    return "\n".join(lines)


def outstanding_attacks(model: ThreatModel, root: Optional[Attack] = None) -> list[Attack]:
    """
    Get outstanding attacks (leaf attacks with no mitigations).

    If root is provided, only consider attacks under that root.
    """
    # Get all attacks to consider
    if root is None:
        attacks_to_check = model.attacks
    else:
        # Collect all descendants of root
        attacks_to_check = []
        _collect_descendants(model, root, attacks_to_check)

    outstanding = []
    for attack in attacks_to_check:
        # Check if it's a leaf (no children)
        children = [a for a in model.attacks if attack in a.achieves or attack in a.requires]
        if children:
            continue  # Not a leaf

        # Check if it has mitigations (direct or inherited)
        mits = model.get_mitigations_for(attack)
        if not mits:
            outstanding.append(attack)

    return outstanding


def outstanding_table(
    model: ThreatModel,
    root: Optional[Attack] = None,
    include_oos_only: bool = False
) -> str:
    """
    Display outstanding attacks in table format.

    Shows attack lineages (paths from root to leaf) for attacks without mitigations.
    Format: RootAttack > ChildAttack (Context) > *Outstanding*

    Args:
        model: The threat model to query
        root: Optional root attack to filter by
        include_oos_only: If True, also includes attacks where ALL mitigations are
            "Out of scope" (effectively unmitigated from a practical standpoint)
    """
    OUTSTANDING = "*Outstanding*"

    # Collect outstanding lines
    lines = []

    if root is None:
        # Get all root attacks (no parents)
        roots = [a for a in model.attacks if not a.achieves and not a.requires]
    else:
        roots = [root]

    for root_attack in roots:
        _collect_outstanding_lines(model, root_attack, [], lines, OUTSTANDING, include_oos_only)

    # Format as table
    return _format_outstanding_table(lines)


def _collect_outstanding_lines(
    model: ThreatModel,
    attack: Attack,
    lineage: list[str],
    result: list[str],
    outstanding_marker: str = "*Outstanding*",
    include_oos_only: bool = False
) -> None:
    """Recursively collect outstanding attack lineages.

    Args:
        include_oos_only: If True, also includes attacks where ALL mitigations
            are "Out of scope" (treating them as effectively outstanding)
    """

    # Build name with context
    if attack.occurs_in:
        name = f"{attack.name} ({', '.join(c.id for c in attack.occurs_in)})"
    else:
        name = attack.name

    current_lineage = lineage + [name]

    # Get children (attacks that achieve or require this one)
    children = [a for a in model.attacks if attack in a.achieves or attack in a.requires]

    # Check if this is an outstanding leaf
    # Outstanding = no children, no mitigations (including OOS!), AND no variant_of
    # Note: OOS still counts as a mitigation for the purpose of "outstanding" check
    has_mitigations = len(attack.mitigations) > 0

    # Check if attack has ONLY "Out of scope" mitigations
    oos_only = False
    if include_oos_only and has_mitigations:
        oos_only = all(ma.mitigation.name == "Out of scope" for ma in attack.mitigations)

    is_outstanding = not children and not has_mitigations and not attack.variant_of
    is_oos_only_leaf = not children and oos_only and not attack.variant_of

    if is_outstanding or is_oos_only_leaf:
        # This is an outstanding attack (or effectively outstanding if OOS-only)
        result.append(" > ".join(current_lineage + [outstanding_marker]))
        return

    # Recurse into children
    for child in children:
        _collect_outstanding_lines(model, child, current_lineage, result, outstanding_marker, include_oos_only)


def _format_outstanding_table(lines: list[str]) -> str:
    """Format outstanding lines as a table."""
    # Find max width
    if lines:
        max_width = max(len(line) for line in lines)
        width = max(22, max_width)  # Minimum width for header
    else:
        width = 20  # "Attack outstanding" is 18 chars

    output = []
    sep = f"+{'-' * (width + 2)}+"
    header_sep = f"+{'=' * (width + 2)}+"

    output.append(sep)
    output.append(f"| {'Attack outstanding'.ljust(width)} |")
    output.append(header_sep)

    for line in sorted(lines):
        output.append(f"| {line.ljust(width)} |")

    output.append(sep)

    return "\n".join(output)


def _collect_descendants(model: ThreatModel, attack: Attack, result: list[Attack]) -> None:
    """Collect attack and all its descendants."""
    result.append(attack)
    children = [a for a in model.attacks if attack in a.achieves or attack in a.requires]
    for child in children:
        _collect_descendants(model, child, result)


def get_attack_identifier(attack: Attack) -> str:
    """
    Build the legacy-style attack identifier.

    Format: ParentName.AttackName or ParentName.AttackName.ContextID

    Examples:
        - Denial of service.Spoofing.VA
        - Malicious reporting.Malicious reporting of VD
        - Internal sabotage.Subsystem sabotage.SUB
    """
    parts = []

    # Get parent name (first achieves)
    if attack.achieves:
        parts.append(attack.achieves[0].name)

    # Add attack name
    parts.append(attack.name)

    # Add context if present
    if attack.occurs_in:
        parts.append(attack.occurs_in[0].id)

    return ".".join(parts)


def get_attacks_for_property(model: ThreatModel, prop: Property) -> list[Attack]:
    """
    Get all attacks that target this specific property.

    Unlike get_attacks_targeting which gets descendants too, this only
    returns attacks that directly target this property.
    """
    return [a for a in model.attacks if prop in a.targets]


def get_mitigations_for_property(model: ThreatModel, prop: Property) -> list[Mitigation]:
    """
    Get unique mitigations for all attacks targeting this property.

    This follows attack hierarchies (children) and pattern hierarchies
    (instance_of/variant_of) to collect all applicable mitigations.
    """
    seen: set[str] = set()
    result: list[Mitigation] = []

    attacks = get_attacks_for_property(model, prop)
    for attack in attacks:
        _collect_attack_mitigations(model, attack, seen, result)

    return result


def _collect_attack_mitigations(
    model: ThreatModel,
    attack: Attack,
    seen: set[str],
    result: list[Mitigation]
) -> None:
    """
    Recursively collect mitigations from an attack and its descendants.

    This mirrors the legacy behavior which collects mitigations from:
    - Direct attack mitigations
    - Child attack mitigations (attacks that achieve this one)
    - Pattern mitigations (via variant_of/instance_of)
    """
    # Get mitigations from this attack (direct + inherited from pattern)
    for mit, _rationale in model.get_mitigations_for(attack, include_inherited=True):
        # Skip OUT_OF_SCOPE - legacy view doesn't show it in property table
        if mit.id not in seen and mit.id != "OOS":
            seen.add(mit.id)
            result.append(mit)

    # Recurse into children (attacks that achieve or require this one)
    children = [a for a in model.attacks if attack in a.achieves or attack in a.requires]
    for child in children:
        _collect_attack_mitigations(model, child, seen, result)


def property_table(model: ThreatModel, root: Optional[Property] = None) -> str:
    """
    Display property table in legacy format.

    Format matches legacy view.py -e property output with columns:
    Name, Description, Attacks, Mitigations

    The table shows tree structure in Name column using └─ prefixes.
    """
    # Get properties in tree order
    if root is None:
        roots = [p for p in model.properties if p.refines is None]
    else:
        roots = [root]

    rows: list[tuple[str, str, list[str], list[str]]] = []

    for r in sorted(roots, key=lambda p: p.id):
        _collect_property_rows(model, r, rows, level=0, prefix="")

    return _format_property_table(rows)


def _collect_property_rows(
    model: ThreatModel,
    prop: Property,
    rows: list[tuple[str, str, list[str], list[str]]],
    level: int,
    prefix: str
) -> None:
    """Recursively collect property rows with tree indentation."""
    # Build name with tree prefix
    if level == 0:
        name = prop.id
        child_prefix = ""
    else:
        name = prefix + prop.id
        child_prefix = prefix + "─"

    # Truncate description
    desc = prop.description[:50] + ".." if len(prop.description) > 50 else prop.description

    # Get attacks targeting this property
    attacks = get_attacks_for_property(model, prop)
    attack_ids = sorted([get_attack_identifier(a) for a in attacks])

    # Get mitigations for this property
    mitigations = get_mitigations_for_property(model, prop)
    mitigation_names = sorted([m.name for m in mitigations])

    rows.append((name, desc, attack_ids, mitigation_names))

    # Process children
    children = sorted(
        [p for p in model.properties if p.refines and p.refines.id == prop.id],
        key=lambda p: p.id
    )

    for child in children:
        if level == 0:
            new_prefix = "└─"
        else:
            new_prefix = child_prefix
        _collect_property_rows(model, child, rows, level + 1, new_prefix)


def _format_property_table(rows: list[tuple[str, str, list[str], list[str]]]) -> str:
    """Format property rows as a table matching legacy output."""
    # Column widths matching legacy output
    name_width = 18
    desc_width = 52
    attack_width = 79
    mit_width = 33

    lines = []

    # Header
    sep = f"+{'-' * (name_width + 2)}+{'-' * (desc_width + 2)}+{'-' * (attack_width + 2)}+{'-' * (mit_width + 2)}+"
    header_sep = f"+{'=' * (name_width + 2)}+{'=' * (desc_width + 2)}+{'=' * (attack_width + 2)}+{'=' * (mit_width + 2)}+"

    lines.append(sep)
    lines.append(f"| {'Name'.ljust(name_width)} | {'Description'.ljust(desc_width)} | {'Attacks'.ljust(attack_width)} | {'Mitigations'.ljust(mit_width)} |")
    lines.append(header_sep)

    for name, desc, attacks, mitigations in rows:
        # Calculate max rows needed for this property
        max_rows = max(1, len(attacks), len(mitigations))

        for i in range(max_rows):
            # First row gets name and description
            if i == 0:
                name_cell = name[:name_width].ljust(name_width)
                desc_cell = desc[:desc_width].ljust(desc_width)
            else:
                name_cell = " " * name_width
                desc_cell = " " * desc_width

            # Attack for this row
            if i < len(attacks):
                attack_cell = attacks[i][:attack_width].ljust(attack_width)
            else:
                attack_cell = " " * attack_width

            # Mitigation for this row
            if i < len(mitigations):
                mit_cell = mitigations[i][:mit_width].ljust(mit_width)
            else:
                mit_cell = " " * mit_width

            lines.append(f"| {name_cell} | {desc_cell} | {attack_cell} | {mit_cell} |")

        lines.append(sep)

    return "\n".join(lines)


def attack_table(model: ThreatModel, root: Optional[Attack] = None) -> str:
    """
    Display attack table in legacy format.

    Format matches legacy view.py -e attack output with columns:
    Attack, Description, Context, Properties

    The table shows tree structure in Attack column using └─ and ├─ prefixes.
    """
    # Get attacks in tree order
    if root is None:
        roots = [a for a in model.attacks if not a.achieves and not a.requires]
    else:
        roots = [root]

    rows: list[tuple[str, str, str, str]] = []

    for r in sorted(roots, key=lambda a: a.name):
        _collect_attack_rows(model, r, rows, level=0, prefix="")

    return _format_attack_table(rows)


def _collect_attack_rows(
    model: ThreatModel,
    attack: Attack,
    rows: list[tuple[str, str, str, str]],
    level: int,
    prefix: str
) -> None:
    """Recursively collect attack rows with tree indentation."""
    # Build name with tree prefix
    if level == 0:
        name = attack.name
        child_prefix = ""
    else:
        name = prefix + attack.name
        child_prefix = prefix[:-1] + "─"  # Continue tree structure

    # Truncate description to 50 chars
    desc = attack.description or ""
    desc = desc[:50] + ".." if len(desc) > 50 else desc

    # Context
    if attack.occurs_in:
        context = ", ".join(c.id for c in attack.occurs_in)
    else:
        context = "None"

    # Properties
    props = ", ".join(p.id for p in attack.targets)

    rows.append((name, desc, context, props))

    # Get children (attacks that achieve or require this one)
    children = sorted(
        [a for a in model.attacks if attack in a.achieves or attack in a.requires],
        key=lambda a: a.name
    )

    for i, child in enumerate(children):
        is_last = (i == len(children) - 1)
        if level == 0:
            new_prefix = "└─" if is_last else "├─"
        else:
            new_prefix = child_prefix
        _collect_attack_rows(model, child, rows, level + 1, new_prefix)


def _format_attack_table(rows: list[tuple[str, str, str, str]]) -> str:
    """Format attack rows as a table matching legacy output."""
    # Column widths matching legacy output
    attack_width = 51
    desc_width = 52
    ctx_width = 9
    props_width = 16

    lines = []

    # Header
    sep = f"+{'-' * (attack_width + 2)}+{'-' * (desc_width + 2)}+{'-' * (ctx_width + 2)}+{'-' * (props_width + 2)}+"
    header_sep = f"+{'=' * (attack_width + 2)}+{'=' * (desc_width + 2)}+{'=' * (ctx_width + 2)}+{'=' * (props_width + 2)}+"

    lines.append(sep)
    lines.append(f"| {'Attack'.ljust(attack_width)} | {'Description'.ljust(desc_width)} | {'Context'.ljust(ctx_width)} | {'Properties'.ljust(props_width)} |")
    lines.append(header_sep)

    for name, desc, context, props in rows:
        name_cell = name[:attack_width].ljust(attack_width)
        desc_cell = desc[:desc_width].ljust(desc_width)
        ctx_cell = context[:ctx_width].ljust(ctx_width)
        props_cell = props[:props_width].ljust(props_width)

        lines.append(f"| {name_cell} | {desc_cell} | {ctx_cell} | {props_cell} |")
        lines.append(sep)

    return "\n".join(lines)


# =============================================================================
# Mitigation views
# =============================================================================

def mitigation_table(
    model: ThreatModel,
    root: Optional[Attack] = None,
    abstract: bool = False,
    include_oos: bool = False
) -> str:
    """
    Display mitigation table in legacy format.

    Format matches legacy view.py -e mitigation output with columns:
    Mitigation, Description, Attack line

    Attack line shows the path from root attack to the mitigation:
    RootAttack > ChildAttack (Context) > MitigationName

    Args:
        model: The threat model
        root: Optional root attack to start from
        abstract: If True, include mitigations from attack patterns (variant_of)
        include_oos: If True, include "Out of scope" mitigations
    """
    # Get attack mitigation lines: list of (mitigation_name, lineage_string)
    lines_by_mitigation: dict[str, list[str]] = {}
    mit_descriptions: dict[str, str] = {}

    # Get root attacks
    if root is None:
        roots = [a for a in model.attacks if not a.achieves and not a.requires]
    else:
        roots = [root]

    for root_attack in roots:
        _collect_mitigation_lines(model, root_attack, [], lines_by_mitigation, mit_descriptions, abstract, include_oos)

    return _format_mitigation_table(lines_by_mitigation, mit_descriptions)


def _get_attack_display_name(attack: Attack) -> str:
    """Get attack name with context for display in lineage."""
    if attack.occurs_in:
        return f"{attack.name} ({', '.join(c.id for c in attack.occurs_in)})"
    return attack.name


def _collect_mitigation_lines(
    model: ThreatModel,
    attack: Attack,
    lineage: list[str],
    lines_by_mitigation: dict[str, list[str]],
    mit_descriptions: dict[str, str],
    abstract: bool = False,
    include_oos: bool = False
) -> None:
    """
    Recursively collect mitigation lines from attack tree.

    Builds attack lineages (paths from root to leaf) and records each
    mitigation found along with its attack path.

    Args:
        model: The threat model
        attack: Current attack being processed
        lineage: Path from root to current attack
        lines_by_mitigation: Accumulator for mitigation lines
        mit_descriptions: Accumulator for mitigation descriptions
        abstract: If True, include mitigations from attack patterns
        include_oos: If True, include "Out of scope" mitigations
    """
    # Build current lineage
    current_name = _get_attack_display_name(attack)
    current_lineage = lineage + [current_name]

    # Record direct mitigations on this attack
    for ma in attack.mitigations:
        if ma.mitigation.id == "OOS" and not include_oos:
            continue  # Skip Out of scope unless requested

        mit_name = ma.mitigation.name
        # Attack line format: root > child > mitigation
        attack_line = " > ".join(current_lineage + [mit_name])

        if mit_name not in lines_by_mitigation:
            lines_by_mitigation[mit_name] = []
            mit_descriptions[mit_name] = ma.mitigation.description or ""

        lines_by_mitigation[mit_name].append(attack_line)

    # If abstract=True, include mitigations from the attack's pattern hierarchy
    if abstract and attack.variant_of:
        # Pass the attack lineage as a base; pattern mitigations will use → separator
        _collect_pattern_mitigations(
            model, attack.variant_of, current_lineage, [],
            lines_by_mitigation, mit_descriptions, include_oos
        )

    # Recurse into children (attacks that achieve or require this one)
    children = [a for a in model.attacks if attack in a.achieves or attack in a.requires]
    for child in children:
        _collect_mitigation_lines(model, child, current_lineage, lines_by_mitigation, mit_descriptions, abstract, include_oos)


def _collect_pattern_mitigations(
    model: ThreatModel,
    pattern: AttackPattern,
    attack_lineage: list[str],
    pattern_lineage: list[str],
    lines_by_mitigation: dict[str, list[str]],
    mit_descriptions: dict[str, str],
    include_oos: bool = False
) -> None:
    """
    Collect mitigations from an attack pattern and its refinements.

    When abstract=True, we need to include mitigations from:
    1. The pattern itself
    2. All patterns that refine this pattern (children in the pattern hierarchy)

    For example, if attack.variant_of = compromised_device, we collect mitigations
    from malware, intrusion, escalation_of_privilege, etc. that refine compromised_device.

    The attack_lineage uses ' > ' separator (direct relationships).
    The pattern_lineage uses ' → ' separator (inheritance chain).
    """
    # Collect mitigations from this pattern
    for ma in pattern.mitigations:
        if ma.mitigation.id == "OOS" and not include_oos:
            continue

        mit_name = ma.mitigation.name
        # Build attack line: attack path > pattern path → mitigation
        attack_part = " > ".join(attack_lineage)
        if pattern_lineage:
            pattern_part = " → ".join(pattern_lineage)
            attack_line = f"{attack_part} → {pattern_part} → {mit_name}"
        else:
            attack_line = f"{attack_part} → {mit_name}"

        if mit_name not in lines_by_mitigation:
            lines_by_mitigation[mit_name] = []
            mit_descriptions[mit_name] = ma.mitigation.description or ""

        lines_by_mitigation[mit_name].append(attack_line)

    # Collect mitigations from patterns that refine this one
    for child_pattern in model.patterns:
        if child_pattern.refines == pattern:
            # Include the child pattern's name in the pattern lineage
            child_pattern_lineage = pattern_lineage + [child_pattern.name]
            _collect_pattern_mitigations(
                model, child_pattern, attack_lineage, child_pattern_lineage,
                lines_by_mitigation, mit_descriptions, include_oos
            )


def _format_mitigation_table(
    lines_by_mitigation: dict[str, list[str]],
    mit_descriptions: dict[str, str]
) -> str:
    """Format mitigation data as a table matching legacy output."""
    # Column widths matching legacy output
    mit_width = 33
    desc_width = 52
    line_width = 90

    lines = []

    # Header
    sep = f"+{'-' * (mit_width + 2)}+{'-' * (desc_width + 2)}+{'-' * (line_width + 2)}+"
    header_sep = f"+{'=' * (mit_width + 2)}+{'=' * (desc_width + 2)}+{'=' * (line_width + 2)}+"

    lines.append(sep)
    lines.append(f"| {'Mitigation'.ljust(mit_width)} | {'Description'.ljust(desc_width)} | {'Attack line'.ljust(line_width)} |")
    lines.append(header_sep)

    # Sort mitigations alphabetically
    for mit_name in sorted(lines_by_mitigation.keys()):
        attack_lines = sorted(lines_by_mitigation[mit_name])
        desc = mit_descriptions.get(mit_name, "")
        desc = desc[:50] + ".." if len(desc) > 50 else desc

        max_rows = max(1, len(attack_lines))

        for i in range(max_rows):
            if i == 0:
                mit_cell = mit_name[:mit_width].ljust(mit_width)
                desc_cell = desc[:desc_width].ljust(desc_width)
            else:
                mit_cell = " " * mit_width
                desc_cell = " " * desc_width

            if i < len(attack_lines):
                line_cell = attack_lines[i][:line_width].ljust(line_width)
            else:
                line_cell = " " * line_width

            lines.append(f"| {mit_cell} | {desc_cell} | {line_cell} |")

        lines.append(sep)

    return "\n".join(lines)


def mitigation_tree(model: ThreatModel, root: Attack) -> str:
    """
    Display mitigation tree in legacy format.

    Shows attack tree with mitigations as leaves.
    Format:
        RootAttack
        ├── ChildAttack (Context)
        │   ├── Mitigation1
        │   └── Mitigation2
        └── ChildAttack2 (Context)
            └── Mitigation3
    """
    lines = []

    # Root attack name
    lines.append(root.name)

    # Get children of the root attack (attacks that achieve or require this one)
    children = [a for a in model.attacks if root in a.achieves or root in a.requires]
    children = sorted(children, key=lambda a: (a.name, ','.join(c.id for c in a.occurs_in) if a.occurs_in else ''))

    for i, child in enumerate(children):
        is_last = (i == len(children) - 1)
        _build_mitigation_tree_node(model, child, lines, "", is_last)

    return "\n".join(lines)


def _build_mitigation_tree_node(
    model: ThreatModel,
    attack: Attack,
    lines: list[str],
    prefix: str,
    is_last: bool
) -> None:
    """Build a node in the mitigation tree."""
    # Connector characters
    branch = "└── " if is_last else "├── "
    child_prefix = prefix + ("    " if is_last else "│   ")

    # Attack name with context
    if attack.occurs_in:
        name = f"{attack.name} ({', '.join(c.id for c in attack.occurs_in)})"
    else:
        name = attack.name

    lines.append(f"{prefix}{branch}{name}")

    # Collect mitigations for this attack
    mitigations = []
    for ma in attack.mitigations:
        if ma.mitigation.id != "OOS":
            mitigations.append(ma.mitigation.name)
    mitigations = sorted(mitigations)

    # Get children of this attack (attacks that achieve or require this one)
    children = [a for a in model.attacks if attack in a.achieves or attack in a.requires]
    children = sorted(children, key=lambda a: (a.name, ','.join(c.id for c in a.occurs_in) if a.occurs_in else ''))

    # Total items (mitigations + children)
    total_items = len(mitigations) + len(children)
    item_idx = 0

    # Show mitigations as leaves
    for mit_name in mitigations:
        item_idx += 1
        is_last_item = (item_idx == total_items)
        mit_branch = "└── " if is_last_item else "├── "
        lines.append(f"{child_prefix}{mit_branch}{mit_name}")

    # Recurse into children
    for child in children:
        item_idx += 1
        is_last_item = (item_idx == total_items)
        _build_mitigation_tree_node(model, child, lines, child_prefix, is_last_item)
