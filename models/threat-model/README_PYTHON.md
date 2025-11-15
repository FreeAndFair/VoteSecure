# NXT

A Python/NetworkX-based threat modeling framework for VoteSecure. Converts threat model definitions into queryable graphs.

## Project Structure

```
threat-model/
├── src/nxt/
│   ├── schema/          # Core type definitions (Property, Attack, Mitigation, etc.)
│   │   ├── types.py     # Pydantic models for all threat model entities
│   │   └── model.py     # ThreatModel container and NetworkX graph builder
│   ├── model/           # Threat model definitions and tools
│   │   ├── properties.py    # Security properties (C1, V1, P1, etc.)
│   │   ├── contexts.py      # System contexts (VA, EAS, BB, etc.)
│   │   ├── mitigations.py   # Mitigation definitions
│   │   ├── patterns.py      # Abstract attack patterns
│   │   ├── attacks.py       # Concrete attack definitions
│   │   ├── view_cli.py      # CLI query tool
│   │   ├── visualize.py     # HTML visualization generator
│   │   └── generate_latex_inputs.py  # LaTeX table generator
├── threat_model.html    # Generated interactive graph visualization
└── threat_model.pdf     # Generated PDF threat model
```

### Schema vs Model

- **`schema/`**: Defines the *structure* - Pydantic types (`Attack`, `Mitigation`, etc.) and the `ThreatModel` class that builds the NetworkX graph.
- **`model/`**: Contains the *content* - actual threat model data (attacks, mitigations, properties) and CLI tools.

## Editing the Threat Model

To add or modify threats, edit files in `src/nxt/model/`:

| To add...       | Edit this file      | Example |
|-----------------|---------------------|---------|
| Attack          | `attacks.py`        | `my_attack = Attack(id="my_attack", name="My Attack", ...)` |
| Mitigation      | `mitigations.py`    | `my_mitigation = Mitigation(id="M99", name="...", ...)` |
| Attack Pattern  | `patterns.py`       | `my_pattern = AttackPattern(id="...", ...)` |
| Property        | `properties.py`     | `X1 = Property(id="X1", refines=PARENT, ...)` |
| Context         | `contexts.py`       | `XYZ = Context(id="XYZ", name="...", kind=ContextKind.SUBSYSTEM)` |

## Running the Tools

All commands should be run from the `src/` directory.

### Query Tool (view_cli.py)

Display threat model data in table or tree format:

```bash
# List all attacks
python -m nxt.model.view_cli -e attack

# Show attack tree starting from a specific attack
python -m nxt.model.view_cli -e attack -r "clash_attack_v2" -t

# Show mitigations for an attack
python -m nxt.model.view_cli -e mitigation -r "bad_mixing"

# Show all properties as a tree
python -m nxt.model.view_cli -e property -t

# Show outstanding (unmitigated) attacks
python -m nxt.model.view_cli -e outstanding
```

Options:
- `-e, --entity`: `attack`, `property`, `mitigation`, `context`, `outstanding`
- `-r, --root`: Start from a specific entity (by ID)
- `-t, --tree`: Display as tree instead of table
- `-o, --oos`: Include "Out of Scope" items

### Text Visualization (server.py)

Run a server to serve a text-based visualization (`--help` will show additional command line options):

```bash
python -m nxt.model.server
```

### Graph Visualization (visualize.py)

Generate an interactive HTML graph visualization:

```bash
python -m nxt.model.visualize -o threat_model.html
```

Open `threat_model.html` in a browser. Features:
- Click nodes to focus on reachable subgraph
- Shift+Click to hide unreachable nodes
- Search panel for finding nodes
- Shareable URLs via `?node=<id>` parameter

## Key Relationships

- **achieves**: Attack → Parent Attack (attack hierarchy)
- **requires**: Attack → Prerequisite Attack (dependencies)
- **variant_of**: Attack → Pattern (attack is instance of pattern)
- **refines**: Pattern → Parent Pattern, Property → Parent Property (inheritance)
- **mitigations**: Attack/Pattern → MitigationApplication (countermeasures)
- **targets**: Attack → Property (what security property is threatened)
- **occurs_in**: Attack → Context (where the attack happens)
