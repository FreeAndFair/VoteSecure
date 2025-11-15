#!/usr/bin/env python
"""
CLI tool for querying threat model views.

This is the modern replacement for legacy/view.py, using NetworkX-based
graph queries instead of SQLite database queries.

Usage: python -m nxt.model.view_cli [-h] [-t] [-e ENTITY] [-r ROOT] [-o] [-a]

Examples:
    python -m nxt.model.view_cli -e property                   # prints all properties table
    python -m nxt.model.view_cli -e property -t                # prints all properties tree
    python -m nxt.model.view_cli -e property -t -r C3          # prints properties tree, starting at 'C3'
    python -m nxt.model.view_cli -e attack                     # prints all attacks table
    python -m nxt.model.view_cli -e attack -t                  # prints all attacks tree
    python -m nxt.model.view_cli -e attack -r bad_mixing       # prints attacks table, starting at 'bad_mixing'
    python -m nxt.model.view_cli -e mitigation                 # prints all mitigations table
    python -m nxt.model.view_cli -e mitigation -r bad_mixing   # prints mitigations table for attack
    python -m nxt.model.view_cli -e mitigation -r bad_mixing -t  # prints mitigations tree for attack
    python -m nxt.model.view_cli -e context                    # prints all contexts
    python -m nxt.model.view_cli -e outstanding                # prints all outstanding attacks

Copyright (C) 2025 Free & Fair
"""

import argparse
import sys

from nxt.model import model as threat_model
from nxt.model import views


def find_property(prop_id: str):
    """Find a property by ID (case-insensitive)."""
    for prop in threat_model.properties:
        if prop.id.upper() == prop_id.upper():
            return prop
    return None


def find_attack(attack_id: str):
    """Find an attack by ID (case-insensitive)."""
    for attack in threat_model.attacks:
        if attack.id.lower() == attack_id.lower():
            return attack
    return None


def show_property_view(args):
    """Display property view (table or tree)."""
    root = None
    if args.root:
        root = find_property(args.root)
        if root is None:
            print(f"Property not found: {args.root}", file=sys.stderr)
            sys.exit(1)

    if args.tree:
        print(views.property_tree(threat_model, root))
    else:
        print(views.property_table(threat_model, root))


def show_attack_view(args):
    """Display attack view (table or tree)."""
    root = None
    if args.root:
        root = find_attack(args.root)
        if root is None:
            print(f"Attack not found: {args.root}", file=sys.stderr)
            sys.exit(1)

    if args.tree:
        print(views.attack_tree(threat_model, root))
    else:
        print(views.attack_table(threat_model, root))


def show_mitigation_view(args):
    """Display mitigation view (table or tree)."""
    root = None
    if args.root:
        root = find_attack(args.root)
        if root is None:
            print(f"Attack not found: {args.root}", file=sys.stderr)
            sys.exit(1)

    if args.tree:
        if root is None:
            print("Error: -r ROOT is required for mitigation tree view", file=sys.stderr)
            sys.exit(1)
        print(views.mitigation_tree(threat_model, root))
    else:
        print(views.mitigation_table(threat_model, root, abstract=args.abstract, include_oos=args.oos))


def show_context_view(args):
    """Display context table."""
    print(views.context_table(threat_model))


def show_outstanding_view(args):
    """Display outstanding attacks."""
    root = None
    if args.root:
        root = find_attack(args.root)
        if root is None:
            print(f"Attack not found: {args.root}", file=sys.stderr)
            sys.exit(1)

    print(views.outstanding_table(threat_model, root, include_oos_only=args.oos))


def main():
    parser = argparse.ArgumentParser(
        description="Display threat model data in table or tree format.",
        epilog="""
Examples:
    %(prog)s -e property                       # prints all properties table
    %(prog)s -e property -t                    # prints all properties tree
    %(prog)s -e property -t -r CONFIDENTIALITY # prints properties tree, starting at 'CONFIDENTIALITY'
    %(prog)s -e attack                         # prints all attacks table
    %(prog)s -e attack -t                      # prints all attacks tree
    %(prog)s -e attack -r "Bad mixing"         # prints attacks table, starting at 'Bad mixing'
    %(prog)s -e mitigation                     # prints all mitigations table
    %(prog)s -e mitigation -r "Bad mixing"     # prints mitigations table for attack 'Bad mixing'
    %(prog)s -e mitigation -r "Bad mixing" -t  # prints mitigations tree for attack 'Bad mixing'
    %(prog)s -e context                        # prints all contexts
    %(prog)s -e outstanding                    # prints all outstanding attacks
    %(prog)s -e outstanding -r "Bad mixing"    # prints outstanding attacks starting at 'Bad mixing'
        """,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument(
        "-t", "--tree",
        action="store_true",
        help="Display data in tree format",
    )

    parser.add_argument(
        "-e", "--entity",
        choices=["property", "context", "mitigation", "attack", "outstanding"],
        required=True,
        help="Specify the entity to display",
    )

    parser.add_argument(
        "-r", "--root",
        type=str,
        help="Specify the root entity by name or ID",
    )

    parser.add_argument(
        "-o", "--oos",
        action="store_true",
        help="Include 'Out of scope' mitigations (for mitigation and outstanding views)",
    )

    parser.add_argument(
        "-a", "--abstract",
        action="store_true",
        help="Include mitigations inherited from attack patterns (for mitigation view)",
    )

    args = parser.parse_args()

    # Dispatch to appropriate view
    if args.entity == "property":
        show_property_view(args)
    elif args.entity == "attack":
        show_attack_view(args)
    elif args.entity == "mitigation":
        show_mitigation_view(args)
    elif args.entity == "context":
        show_context_view(args)
    elif args.entity == "outstanding":
        show_outstanding_view(args)


if __name__ == "__main__":
    main()
