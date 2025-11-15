#!/usr/bin/env python

# Flask Server for Threat Model Visualization
# Copyright (C) 2025-26 Free & Fair
# Last Revised 3 February 2026 by Daniel M. Zimmerman

import argparse
from natsort import natsorted
from flask import Flask, jsonify, send_from_directory
from waitress import serve

# our shared data structures (via compatibility layer)
from .compat import get_legacy_data

app = Flask(__name__)
STATIC_FOLDER = 'static'  # Folder where the front-end HTML is located

# Global data structures
property_dict = None
context_dict = None
mitigation_dict = None
attack_dict = None

mit_out_of_scope = {
    'id': None,
    'auto_identifier': 'OOS',
    'name': 'Out of Scope',
    'description': 'Mitigating this attack is outside the scope of the E2E-VIV cryptographic core library.',
    'attacks': []
}

def initialize_data():
    """Initialize data structures on server startup."""
    global property_dict
    global context_dict
    global mitigation_dict
    global attack_dict
    property_dict, context_dict, mitigation_dict, attack_dict = get_legacy_data()

@app.route('/')
@app.route('/view_properties.html')
def serve_properties_view():
    """Serve the static HTML file."""
    return send_from_directory(STATIC_FOLDER, 'view_properties.html')

@app.route('/view_attacks.html')
def serve_attacks_view():
    """Serve the static HTML file."""
    return send_from_directory(STATIC_FOLDER, 'view_attacks.html')

@app.route('/view_mitigations.html')
def serve_mitigations_view():
    """Serve the static HTML file."""
    return send_from_directory(STATIC_FOLDER, 'view_mitigations.html')

@app.route('/marked.min.js')
def serve_marked_javascript():
    """Serve the static Javascript file."""
    return send_from_directory(STATIC_FOLDER, 'marked.min.js')

def serialize_property(property_obj):
    """Serialize property objects to avoid circular references."""
    return {
        'id': property_obj['id'],
        'auto_identifier': property_obj['auto_identifier'],
        'name': property_obj['name'],
        'description': property_obj['description'],
        'kind': property_obj['kind'],
        'children': [serialize_property(child) for child in property_obj['children']]
    }

def serialize_attack(attack_obj):
    """Serialize attack objects to avoid circular references."""
    mitigations = []
    for m in attack_obj['mitigations']:
        if m['mitigation'] is None:
            mitigations.append({'id': None, 'name': 'Out of Scope'})
        else:
            mitigations.append({'id': m['mitigation']['id'], 'name': m['mitigation']['name']})

    return {
        'id': attack_obj['id'],
        'auto_identifier': attack_obj['auto_identifier'],
        'identifier': attack_obj['identifier'],
        'name': attack_obj['name'],
        'description': attack_obj['description'],
        'is_abstract': attack_obj['is_abstract'],
        'mitigations': mitigations
    }

def serialize_mitigation(mitigation_obj):
    """Serialize mitigation objects to avoid circular references."""
    attacks = []
    for a in mitigation_obj['attacks']:
        attacks.append({
            'id': a['id'],
            'auto_identifier': a['auto_identifier'],
            'identifier': a['identifier'],
            'name': a['name'],
            'description': a['description']
            })
    return {
        'id': mitigation_obj['id'],
        'auto_identifier': mitigation_obj['auto_identifier'],
        'name': mitigation_obj['name'],
        'description': mitigation_obj['description']
    }

@app.route('/properties')
def get_properties():
    """Return the property tree, limited to 'Model' kind."""
    global property_dict
    tree = [serialize_property(prop) for prop in property_dict.values() if prop['parent'] is None and prop['kind'] == 'Model']
    return jsonify(tree)

def collect_attacks(property_obj):
    """Recursively collect attacks from the given property and its descendants."""
    attacks = list(property_obj['attacks'])
    for child in property_obj['children']:
        attacks.extend(collect_attacks(child))
    return attacks

@app.route('/property/<int:property_id>/attacks')
def get_property_attacks(property_id):
    """Return attacks associated with a specific property and its descendants, sorted by identifier."""
    global property_dict
    property_item = property_dict.get(property_id)
    if not property_item:
        return jsonify([])

    # Collect attacks from the property and its entire subtree
    attacks = collect_attacks(property_item)

    # Sort attacks alphabetically by identifier
    sorted_attacks = natsorted(attacks, key=lambda attack: attack['auto_identifier'] or '')
    return jsonify([serialize_attack(attack) for attack in sorted_attacks])

def collect_mitigations(attack_obj):
    """Recursively collect mitigations from an attack and its children."""
    global mit_out_of_scope
    mitigations = {}
    for mit in attack_obj['mitigations']:
        if mit['mitigation'] is not None:
            mitigations[mit['mitigation']['auto_identifier']] = mit
        else:
            mitigations[None] = mit_out_of_scope.copy()
            mitigations[None]['rationale'] = mit['rationale']

    for child in attack_obj['children']:
        child_mitigations = collect_mitigations(child)
        mitigations.update(child_mitigations)
    return mitigations

@app.route('/attack/<int:attack_id>/mitigations')
def get_attack_mitigations(attack_id):
    """Return mitigations for an attack, including child attacks recursively."""
    global mitigation_dict
    global attack_dict
    global mit_out_of_scope
    attack = attack_dict.get(attack_id)
    if not attack:
        return jsonify([])

    # Collect all mitigations from this attack and its descendants
    mitigations = collect_mitigations(attack)

    # If there's more than one mitigation, eliminate any that have key "None"
    if len(mitigations) > 1 and None in mitigations:
        del mitigations[None]

    # Return unique mitigations
    if None in mitigations:
        # None must be the only thing there, so it's out of scope.
        result = mit_out_of_scope.copy()
        result['rationale'] = mitigations[None]['rationale']
        return jsonify([result])
    else:
        return jsonify([{
            'id': mitigation['mitigation']['id'],
            'auto_identifier': mitigation['mitigation']['auto_identifier'],
            'name': mitigation['mitigation']['name'],
            'description': mitigation['mitigation']['description'],
            'rationale': mitigation['rationale']
        } for mitigation in mitigations.values()])

def collect_properties(attack_obj):
    """Recursively collect properties from an attack and its children."""
    properties = {prop['id']: prop for prop in attack_obj['properties']}
    for child in attack_obj['children']:
        child_properties = collect_properties(child)
        properties.update(child_properties)
    return properties

@app.route('/attack/<int:attack_id>/properties')
def get_attack_properties(attack_id):
    """Return properties implicated in a subtree of attacks."""
    global attack_dict
    attack = attack_dict.get(attack_id)
    if not attack:
        return jsonify([])

    # Collect all properties from the attack and its subtree
    properties = collect_properties(attack)
    return jsonify([serialize_property(prop) for prop in properties.values()])

def serialize_attack_tree(attack_obj):
    """Serialize attack objects for the attack tree view."""
    children = [atk for atk in attack_obj['children']]
    sorted_children = natsorted(children, key=lambda attack: attack['auto_identifier'] or '')
    return {
        'id': attack_obj['id'],
        'auto_identifier': attack_obj['auto_identifier'],
        'identifier': attack_obj['identifier'],
        'description': attack_obj['description'],
        'children': [serialize_attack_tree(child) for child in sorted_children]
    }

@app.route('/attacks')
def get_attacks():
    """Return the attack tree."""
    global attack_dict
    # Get all root-level attacks (those without parents)
    roots = [atk for atk in attack_dict.values() if not atk['parents']]
    sorted_roots = natsorted(roots, key=lambda attack: attack['auto_identifier'] or '')
    return jsonify([serialize_attack_tree(root) for root in sorted_roots])

def get_rationale_for_mitigation(attack, mitigation_id, default_rationale=None):
    for mtg in attack['mitigations']:
        if mtg['mitigation'] is not None and mitigation_id == mtg['mitigation']['id']:
            return mtg['rationale']
    return default_rationale

def get_child_attacks_for_mitigation(parent, mitigation_id, rationale):
    result = []
    for child in parent['children']:
        # by default, the child inherits the parent's rationale
        child_rationale = get_rationale_for_mitigation(child, mitigation_id, rationale)
        result.append({
            'id': child['id'],
            'auto_identifier': child['auto_identifier'],
            'identifier': child['identifier'],
            'description': child['description'],
            'rationale': child_rationale
        })
        result.extend(get_child_attacks_for_mitigation(child, mitigation_id, child_rationale))
        if child['is_abstract']:
            result.extend(get_instance_attacks_for_mitigation(child, mitigation_id, child_rationale))
    return result

def get_instance_attacks_for_mitigation(abstract, mitigation_id, rationale):
    result = []
    for instance in attack_dict.values():
        if instance['instance_of'] == abstract:
            # it's an instance of the abstract attack
            instance_rationale = get_rationale_for_mitigation(instance, mitigation_id, rationale)
            result.append({
                'id': instance['id'],
                'auto_identifier': instance['auto_identifier'],
                'identifier': instance['identifier'],
                'description': instance['description'],
                'rationale': instance_rationale
            })
            result.extend(get_child_attacks_for_mitigation(instance, mitigation_id, instance_rationale))
    return result

@app.route('/mitigation/<int:mitigation_id>/attacks')
def get_mitigation_attacks(mitigation_id):
    """Return a list of attacks that are mitigated by the specified mitigation."""
    global attack_dict

    attacks = []
    for atk in attack_dict.values():
        if atk['mitigations'] is not None:
            # There are some mitigations to iterate over
            for mtg in atk['mitigations']:
                if mtg['mitigation'] is not None and mitigation_id == mtg['mitigation']['id']:
                    # We're ignoring "out of scope" mitigations in this view
                    attacks.append({
                        'id': atk['id'],
                        'auto_identifier': atk['auto_identifier'],
                        'identifier': atk['identifier'],
                        'description': atk['description'],
                        'rationale': mtg['rationale']
                    })
                    attacks.extend(get_child_attacks_for_mitigation(atk, mitigation_id, mtg['rationale']))
                    if atk['is_abstract']:
                        attacks.extend(get_instance_attacks_for_mitigation(atk, mitigation_id, mtg['rationale']))

    sorted_attacks = natsorted(attacks, key=lambda attack: attack['auto_identifier'] or '')
    return jsonify(sorted_attacks)

@app.route('/mitigations')
def get_mitigations():
    """Return the mitigation "tree"."""
    global mitigations_dict
    # Get all mitigations
    mitigations = [mit for mit in mitigation_dict.values()]
    sorted_mitigations = natsorted(mitigations, key = lambda mitigation: mitigation['auto_identifier'] or '')
    return jsonify([serialize_mitigation(mit) for mit in sorted_mitigations])


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Run server for interactive browser-based threat model view.')
    parser.add_argument('-p', '--port', type=int, help='Port on which to run the server', nargs='?', default=8911)
    parser.add_argument('--debug', action='store_true', help='Debugging mode')

    args = parser.parse_args()

    with app.app_context():
        initialize_data()
    if args.debug:
        # Serve in flask dev server in debug mode
        app.run(debug=args.debug, port=args.port)
    else:
        # Serve in Waitress WSGI server in regular mode
        serve(app, host='0.0.0.0', port=args.port)
