#!/usr/bin/env python

# This script generates an AdvoCATE assurance case skeleton from the threat
# model database, consisting of the following files:
#
# E2E-VIV_FunctionalArchitecture.functionalarchitecture: the "functional
# architecture" of the system.
#
# E2E-VIV_SafetyArchitecture.safetyarch: the "safety architecture" of the
# system
#
# E2E-VIV_Requirements.requirements: the "requirements log" of the system
#
# E2E-VIV_Argument.argument: the base assurance argument of the system
#
# For a more comprehensive description of these files, see the README.
# For command line usage information, run the script with no command
# line arguments.
#
# Daniel M. Zimmerman, February 2026
# Copyright (C) 2025-26 Free & Fair

import argparse
import os
import re
import sys
from collections import defaultdict
from natsort import natsorted

# our shared data structures (from new Python model via compatibility layer)
from nxt.model.compat import get_legacy_data

# Python version check
if sys.version_info[0] != 3 or sys.version_info[1] < 12:
    print("This script requires Python 3 version 3.12 or higher for PEP-701 compliance.")
    sys.exit(1)

# Regex to match letter-digit identifiers (e.g., A1, C1.1).
LETTER_DIGIT_RE = re.compile(r'^[A-Z]\d+[\.\d+]*')

# Prefix for the output files.
OUTPUT_PREFIX = 'E2E-VIV'

# Dict from security objectives (AdvoCATE "deviations") to security objective
# categories (AdvoCATE "functions"); this is populated during execution of
# generate_functional_architecture.
DEVIATIONS_TO_FUNCTIONS = {}

# Dict from security objectives (AdvoCATE "deviations") to security objectives
# that are implied by them. For example, an attack on C3.1 is implicitly also
# an attack on C3.1.1 and C3.1.2, and an attack on C3.1.2 is implicitly also
# an attack on C3.1 and C3.
IMPLIED_DEVIATIONS = {}

# Dict from requirement names to lists of requirement sources; this is
# populated during execution of generate_safety_architecture.
REQS_TO_SOURCES = {}

# The "out of scope" mitigation.
OUT_OF_SCOPE_MITIGATION = {
    'auto_identifier': 'OOS',
    'name': 'Out of scope',
    'scope': 'oos', # note: oos is not a valid scope, but we're only using it here as a flag
    'description': 'The system cannot mitigate this attack.'
}

# The first part of the argument skeleton (it's always the same so there's no
# point in generating it programmatically).
ARGUMENT_HEADER = '''argument 1.4 E2E-VIV_SecurityArgument

goal G_SECURITY_OBJECTIVES {
	description "The E2E-VIV system meets all its security objectives."
}
strategy S_DIVIDE_BY_SCOPE {
	description "Divide security objectives into those that are entirely within (core), partially within (partially-core, or entirely outside (non-core) the scope of the core cryptographic library."
}
isSupportedBy ISB_DIVIDE_BY_SCOPE_SECURITY_OBJECTIVES {
	to S_DIVIDE_BY_SCOPE from G_SECURITY_OBJECTIVES
}
goal G_SECURITY_OBJECTIVES_CORE {
    description "The system meets all security objectives that are entirely within the scope of the core cryptographic library."
}
goal G_SECURITY_OBJECTIVES_PARTIALLY_CORE {
    description "The system meets all security objectives that are partially within the scope of the core cryptographic library."
}
goal G_SECURITY_OBJECTIVES_NON_CORE {
    description "The system meets all security objectives that are entirely outside the scope of the core cryptographic library."
}
isSupportedBy ISB_SECURITY_OBJECTIVES_CORE_DIVIDE_BY_SCOPE {
    to G_SECURITY_OBJECTIVES_CORE from S_DIVIDE_BY_SCOPE
}
isSupportedBy ISB_SECURITY_OBJECTIVES_PARTIALLY_CORE_DIVIDE_BY_SCOPE {
    to G_SECURITY_OBJECTIVES_PARTIALLY_CORE from S_DIVIDE_BY_SCOPE
}
isSupportedBy ISB_SECURITY_OBJECTIVES_NON_CORE_DIVIDE_BY_SCOPE {
    to G_SECURITY_OBJECTIVES_NON_CORE from S_DIVIDE_BY_SCOPE
}
strategy S_MITIGATIONS_CORE {
    description "Implement core mitigations entirely within the core cryptographic library."
}
strategy S_MITIGATIONS_PARTIALLY_CORE_WITHIN {
    description "Implement partially-core mitigations partially within the core cryptographic library."
}
strategy S_MITIGATIONS_PARTIALLY_CORE_OUTSIDE {
    description "Implement partially-core mitigations partially outside the core cryptographic library."
}
strategy S_MITIGATIONS_NON_CORE {
    description "Implement non-core mitigations outside the core cryptographic library."
}
isSupportedBy ISB_MITIGATIONS_SECURITY_OBJECTIVES_CORE {
    to S_MITIGATIONS_CORE from G_SECURITY_OBJECTIVES_CORE
}
isSupportedBy ISB_MITIGATIONS_SECURITY_OBJECTIVES_PARTIALLY_CORE_WITHIN {
    to S_MITIGATIONS_PARTIALLY_CORE_WITHIN from G_SECURITY_OBJECTIVES_PARTIALLY_CORE
}
isSupportedBy ISB_MITIGATIONS_SECURITY_OBJECTIVES_PARTIALLY_CORE_OUTSIDE {
    to S_MITIGATIONS_PARTIALLY_CORE_OUTSIDE from G_SECURITY_OBJECTIVES_PARTIALLY_CORE
}
isSupportedBy ISB_MITIGATIONS_SECURITY_OBJECTIVES_NON_CORE {
    to S_MITIGATIONS_NON_CORE from G_SECURITY_OBJECTIVES_NON_CORE
}
'''  # end ARGUMENT_HEADER

def collect_descendants(prop):
    """
    Recursively collect all descendant properties of a given property.
    """
    results = []
    stack = list(prop.get('children', []))
    while stack:
        c = stack.pop()
        results.append(c)
        stack.extend(c.get('children', []))
    return results

def collect_ancestors(prop):
    """
    Recursively collect ancestor properties of a given property that
    match LETTER_DIGIT_RE.
    """
    results = []
    prop = prop.get('parent', None)
    while prop is not None and LETTER_DIGIT_RE.match(prop['auto_identifier']):
        results.append(prop)
        prop = prop.get('parent', None)
    return results

def get_indent_level(prop):
    """
    Compute depth from root by following parent pointers until we reach one that
    is not letter-digit.
    """
    depth = 1
    current = prop
    while True:
        parent = current.get('parent')
        if not parent or not LETTER_DIGIT_RE.match(parent['auto_identifier']):
            break
        current = parent
        depth += 1
    return depth

def sanitize_text(txt):
    """
    Replace characters in text that we do not want in AdvoCATE strings.
    """
    return (txt or "").replace('{', '').replace('}', '').replace('"', '\\"').replace('---', '—')

def sanitize_id(raw):
    """
    Replace dots with underscores to make legal AdvoCATE identifiers.
    """
    return raw.replace('.', '_')

def requirement_for_id(id):
    return f"{sanitize_id(id)}_Implementation"

def functional_architecture(properties, mitigations, output_path):
    """
    Generate the AdvoCATE functional architecture.
    """
    # Prepare list of letter-digit deviations.
    deviations = [p for p in properties.values() if LETTER_DIGIT_RE.match(p['auto_identifier'])]
    deviations = natsorted(deviations, key=lambda p: p['auto_identifier'])

    with open(output_path, 'w', encoding='utf-8', newline='\n') as f:
        # Emit header information.
        f.write('functional architecture 1.2 E2E-VIV_FunctionalArchitecture\n\n')
        # Emit deviations with proper indentation.
        for p in deviations:
            indent = get_indent_level(p)
            indent_str = '    ' * indent
            desc = p.get('description', '').replace('{', '').replace('}', '').replace('"', '\\"')
            dev_id = p['auto_identifier'].lower().replace('.', '_')
            f.write(f"{indent_str}deviation {dev_id} \"{desc}\"\n")
        f.write('\n')

        # Determine function roots: model properties that are not letter-digit and that have
        # at least one letter-digit child.
        roots = []
        for p in properties.values():
            if p.get('kind') != 'Model' or LETTER_DIGIT_RE.match(p.get('auto_identifier')):
                continue
            if any(LETTER_DIGIT_RE.match(c['auto_identifier']) for c in p.get('children', [])):
                roots.append(p)
        roots = natsorted(roots, key=lambda p: p['auto_identifier'])

        # Emit one function per root.
        for root in roots:
            fid = sanitize_id(root['auto_identifier']).lower()
            description = root['identifier'].replace('_', ' ').title()
            descendants = collect_descendants(root)
            ids = [sanitize_id(d['auto_identifier']).lower()
                   for d in descendants
                   if LETTER_DIGIT_RE.match(d['auto_identifier'])]
            ids = natsorted(ids)
            # Add these deviations to the deviations-to-functions and implied deviations
            # dictionaries. We populate the implied deviations dictionary even if we're
            # not going to use it later.
            for id in ids:
                DEVIATIONS_TO_FUNCTIONS[id] = fid
            for d in descendants:
                implied = collect_descendants(d)
                implied.extend(collect_ancestors(d))
                IMPLIED_DEVIATIONS[d['auto_identifier']] = implied
            f.write(f"function {fid} \"{description}\" system {{\n")
            f.write(f"    deviations [{', '.join(ids)}]\n")
            f.write("}\n\n")

        # Emit one function for each value in the "scope" column of the mitigations table.
        scopes = set(mit['scope'] for mit in mitigations.values())
        for scope in scopes:
            fid = sanitize_id(scope).lower()
            description = f'{scope} functionality'
            f.write(f"function {fid} \"{description}\" system\n\n")

def safety_architecture(implied_objectives, attacks, augmented_mitigations, output_path):
    """
    Generate the AdvoCATE safety architecture.
    """
    # Identify "root" hazardous activities: concrete attacks with children.
    roots = [
        atk for atk in attacks.values()
        if not atk['is_abstract'] and atk.get('children')
    ]
    roots = natsorted(roots, key=lambda a: sanitize_id(a['auto_identifier']))

    generated_events = []

    with open(output_path, 'w', encoding='utf-8', newline='\n') as f:
        # Emit header and other preset information.
        f.write('safety architecture 1.9 "E2E-VIV_SafetyArchitecture"\n')
        f.write('system state SS "System State"\n')
        f.write('environmental condition EC "Environmental Condition"\n\n')

        # Emit a hazardous activity for each root identifier.
        for root in roots:
            root_id = sanitize_id(root['auto_identifier'])
            # We use the verbose identifier of the root attack as the description.
            root_desc = sanitize_text(root.get('identifier'))

            f.write(f'hazardous activity {root_id} {{\n')
            f.write(f'    description "{root_desc}"\n')
            f.write('    associated argument "E2E-VIV_SecurityArgument"\n')
            f.write('    CES CES1 {\n')
            f.write('        system state SS\n')
            f.write('        environmental condition EC\n\n')

            # Collect all (child, property) pairs and sort by child id
            # then property id.
            pairs = []
            id_pairs = set()
            for child in root.get('children', []):
                if child['is_abstract']:
                    continue
                child_clean = sanitize_id(child['auto_identifier'])
                # Find each property the child attack targets.
                for prop in (child.get('properties') or []):
                    prop_id = prop['auto_identifier']
                    prop_clean = sanitize_id(prop_id)
                    pairs.append((child, prop_clean))
                    id_pairs.add((child_clean, prop_clean))
                    # If we need to include implied properties then
                    # append all of those as well, deduplicating
                    # while doing so.
                    if implied_objectives:
                        for imp in (IMPLIED_DEVIATIONS[prop_id] or []):
                            imp_clean = sanitize_id(imp['auto_identifier'])
                            if (child_clean, imp_clean) not in id_pairs:
                                pairs.append((child, imp_clean))
                                id_pairs.add((child_clean, imp_clean))

            pairs = natsorted(pairs, key=lambda cp: (sanitize_id(cp[0]['auto_identifier']), cp[1]))

            # Generate hazards and associated events, as well as
            # control/barrier/link blocks.
            counter = defaultdict(int)

            for child, prop in pairs:
                c_clean = sanitize_id(child['auto_identifier'])
                evt_id = f"{c_clean}_{prop}"
                # Record for later global event block.
                generated_events.append({
                    'id': evt_id,
                    'description': child.get('description'),
                    'allocation': f"E2E-VIV_FunctionalArchitecture.{DEVIATIONS_TO_FUNCTIONS[prop.lower()]}",
                    'deviation': f"E2E-VIV_FunctionalArchitecture.{prop.lower()}"
                })

                # One control/barrier per mitigation (including inherited ones
                # from abstract attacks).
                raw_child_mitigations = child.get('mitigations', [])
                child_mitigations = [r['mitigation'] for r in raw_child_mitigations]
                if child['instance_of'] is not None:
                    abstracts = [child['instance_of']]
                    abstracts.extend(collect_descendants(child['instance_of']))
                    for a in abstracts:
                        raw_mits = a['mitigations']
                        mits = [r['mitigation'] for r in raw_mits]
                        child_mitigations.extend(mits)
                child_mitigations = [c for c in child_mitigations if c is not None]

                # Deduplicate the list of mitigations; because it's a list of unhashable structs
                # we need to deduplicate their auto_identifiers instead
                deduplicated_child_mitigations = []
                deduplicated_ids = set()
                for mit in child_mitigations:
                    if mit['auto_identifier'] not in deduplicated_ids:
                        deduplicated_ids.add(mit['auto_identifier'])
                        deduplicated_child_mitigations.append(mit)

                # Sort mitigations by auto_identifier
                deduplicated_child_mitigations = \
                    natsorted(deduplicated_child_mitigations, key = lambda value: value['auto_identifier'])

                # if there are no mitigations, the hazard has no associated argument nodes;
                # otherwise, it has one or two per mitigation, depending on the mitigation's scope

                if len(deduplicated_child_mitigations) == 0:
                    f.write(f'        hazard "{evt_id}" of {evt_id}\n')
                    # We throw a None in, so that "out of scope" gets properly linked later.
                    deduplicated_child_mitigations = [ None ]
                else:
                    # Generate the associated argument node name line.
                    aan_names = []
                    for am in deduplicated_child_mitigations:
                        mid = am['auto_identifier']
                        match am['scope']:
                            case 'core' | 'non-core':
                                aan_names.append(f'"E2E-VIV_SecurityArgument.G_IMPLEMENT_{mid}"')

                            case 'partially-core':
                                aan_names.append(f'"E2E-VIV_SecurityArgument.G_IMPLEMENT_{mid}_WITHIN"')
                                aan_names.append(f'"E2E-VIV_SecurityArgument.G_IMPLEMENT_{mid}_OUTSIDE"')

                            case _:
                                print(f'invalid scope {mit['scope']}, aborting.')
                                exit(1)

                    f.write(f'        hazard "{evt_id}" of {evt_id} {{\n')
                    f.write(f'            associated argument nodes {', '.join(aan_names)}\n')
                    f.write('        }\n')

                for am in deduplicated_child_mitigations:
                    mit = am or OUT_OF_SCOPE_MITIGATION
                    mid = mit['auto_identifier']
                    mid_clean = sanitize_id(mid)
                    counter[mid_clean] += 1
                    idx = counter[mid_clean]
                    ctl = f"C_{mid_clean}-{idx}"
                    bar = f"{mid_clean}-{idx}"

                    f.write(f'        control instance "{ctl}" {{\n')
                    f.write(f'            control C_{mid_clean}\n')
                    f.write(f'            barrier "{bar}"\n')
                    f.write('        }\n')

                    f.write(f'        barrier instance "{bar}" of {mid_clean} {{\n')
                    req_id = requirement_for_id(mid)
                    full_req_id = f'E2E-VIV_Requirements.{req_id}'
                    f.write(f'            requirement "{full_req_id}"\n')
                    f.write('        }\n')

                    f.write(f'        link L_{root_id}_ADV_TO_{ctl} from ADV_ACTION_{root_id} to "{ctl}"\n')
                    f.write(f'        link L_{ctl}_TO_{evt_id} from "{ctl}" to {evt_id}\n\n')

                    # Save the sources for requirements to be used later.
                    src = f'E2E-VIV_SafetyArchitecture.{root_id}.{bar}'
                    req_src_list = REQS_TO_SOURCES.get(req_id) or []
                    req_src_list.append(src)
                    REQS_TO_SOURCES[req_id] = req_src_list

            # Adversary event instance for this hazardous activity.
            f.write(f'        event instance ADV_ACTION_{root_id} of ADV_ACTION\n')
            f.write('    }\n')  # End of CES.
            f.write('}\n\n')   # End of hazardous activity.

        # Global event definitions.
        f.write('source ADV description "Election Adversary"\n')
        f.write('event ADV_ACTION { description "Adversary Action" type [security, functional] }\n\n')

        # Emit each duplicated event, allocation, and deviation; deduplicate while
        # preserving order.
        seen = set()
        generated_events = natsorted(generated_events, key = lambda value: value['id'])
        for ev in generated_events:
            eid = ev['id']
            if eid in seen:
                continue
            seen.add(eid)
            desc = sanitize_text(ev['description'])
            alloc = ev['allocation']
            dev = ev['deviation']
            f.write(f'event {eid} {{\n')
            f.write(f'    description "{desc}"\n')
            f.write('    type [security, functional]\n')
            f.write('    sources [ ADV ]\n')
            f.write(f'    allocation "{alloc}"\n')
            f.write(f'    deviation "{dev}"\n')
            f.write('}\n\n')

        # Emit a control block for each mitigation (including OOS).
        sorted_augmented_mitigations = \
            natsorted(augmented_mitigations.values(), key = lambda value: value['auto_identifier'])
        for mit in sorted_augmented_mitigations:
            mid = sanitize_id(mit['auto_identifier'])
            name = sanitize_text(mit['name'])
            f.write(f'control C_{mid} {{\n')
            f.write(f'    description "{name} implemented."\n')
            f.write(f'    barrier {mid}\n')
            f.write('}\n\n')

        # Emit mitigation definitions (including OOS).
        for mit in sorted_augmented_mitigations:
            mid = sanitize_id(mit['auto_identifier'])
            name = sanitize_text(mit['name'])
            scope = mit.get('scope')
            alloc = f"E2E-VIV_FunctionalArchitecture.{scope}" if scope else ''
            f.write(f'mitigation {mid} {{\n')
            f.write(f'    description "{name}"\n')
            if alloc:
                f.write(f'    function allocations [ "{alloc}" ]\n')
            f.write('}\n\n')

def requirements_log(mitigations, output_path):
    """
    Generate the AdvoCATE requirements log.
    """
    with open(output_path, 'w', encoding='utf-8', newline='\n') as f:
        # Emit header.
        f.write('requirements log 1.4 "E2E-VIV_Requirements"\n\n')

        # For each mitigation, we need to generate a requirement; we also
        # need to link it to the hazard log using the sources in REQ_SOURCES
        sorted_mitigations = natsorted(mitigations.values(), key = lambda value: value['auto_identifier'])

        for mit in sorted_mitigations:
            mid = sanitize_id(mit['auto_identifier'])
            req = requirement_for_id(mid)
            sid = sanitize_id(mit['scope'])
            name = sanitize_text(mit['name'])
            desc = sanitize_text(mit['description'])
            quoted_sources = [f'"{s}"' for s in (REQS_TO_SOURCES.get(req) or [])]
            sources = ", ".join(quoted_sources)

            f.write(f'requirement {req} {{\n')
            f.write(f'    description "{mid} - {name}: {desc}"\n')
            f.write('    type security, functional;\n')
            f.write(f'    source {sources};\n')
            f.write(f'    allocation "E2E-VIV_FunctionalArchitecture.{sid}";\n')

            match mit['scope']:
                case 'core' | 'non-core':
                    f.write(f'    relatedArgumentNode [ "E2E-VIV_SecurityArgument.G_IMPLEMENT_{mid}" ]\n}}\n\n')

                case 'partially-core':
                    f.write(f'    relatedArgumentNode [ "E2E-VIV_SecurityArgument.G_IMPLEMENT_{mid}_WITHIN", "E2E-VIV_SecurityArgument.G_IMPLEMENT_{mid}_OUTSIDE" ]\n}}\n\n')

                case 'oos':
                    f.write('}\n\n') # the OOS mitigation isn't related to any argument node

                case _:
                    print(f'invalid scope {mit['scope']}, aborting.')
                    exit(1)

def argument(mitigations, output_path):
    """
    Generate the AdvoCATE argument skeleton.
    """

    sorted_mitigations = natsorted(mitigations.values(), key = lambda m: m['auto_identifier'])

    # open output
    with open(output_path, 'w', encoding='utf-8', newline='\n') as f:
        # write static header
        f.write(ARGUMENT_HEADER)

        for mit in sorted_mitigations:
            mid = sanitize_id(mit['auto_identifier'])
            name = sanitize_text(mit['name'])
            f.write("\n")

            match mit['scope']:
                case 'core':
                    # goal
                    f.write(f"goal toBeDeveloped G_IMPLEMENT_{mid} {{\n")
                    f.write(f"    description \"Implement mitigation {mid} ({name}) within the core cryptographic library.\"\n")
                    f.write("}\n")
                    # link
                    f.write(f"isSupportedBy ISB_IMPLEMENT_{mid}_MITIGATIONS_CORE {{\n")
                    f.write(f"    to G_IMPLEMENT_{mid} from S_MITIGATIONS_CORE\n")
                    f.write("}\n")

                case 'partially-core':
                    # within goal
                    f.write(f"goal toBeDeveloped G_IMPLEMENT_{mid}_WITHIN {{\n")
                    f.write(f"    description \"Implement mitigation {mid} ({name}) within the core cryptographic library.\"\n")
                    f.write("}\n")
                    f.write(f"isSupportedBy ISB_IMPLEMENT_{mid}_MITIGATIONS_PARTIALLY_CORE_WITHIN {{\n")
                    f.write(f"    to G_IMPLEMENT_{mid}_WITHIN from S_MITIGATIONS_PARTIALLY_CORE_WITHIN\n")
                    f.write("}\n\n")
                    # outside goal
                    f.write(f"goal toBeDeveloped G_IMPLEMENT_{mid}_OUTSIDE {{\n")
                    f.write(f"    description \"Implement mitigation {mid} ({name}) outside the core cryptographic library.\"\n")
                    f.write("}\n")
                    f.write(f"isSupportedBy ISB_IMPLEMENT_{mid}_MITIGATIONS_PARTIALLY_CORE_OUTSIDE {{\n")
                    f.write(f"    to G_IMPLEMENT_{mid}_OUTSIDE from S_MITIGATIONS_PARTIALLY_CORE_OUTSIDE\n")
                    f.write("}\n")

                case 'non-core':
                    f.write(f"goal toBeDeveloped G_IMPLEMENT_{mid} {{\n")
                    f.write(f"    description \"Implement mitigation {mid} ({name}) outside the core cryptographic library.\"\n")
                    f.write("}\n")
                    f.write(f"isSupportedBy ISB_IMPLEMENT_{mid}_MITIGATIONS_NON_CORE {{\n")
                    f.write(f"    to G_IMPLEMENT_{mid} from S_MITIGATIONS_NON_CORE\n")
                    f.write("}\n")


                case 'oos':
                    pass # do nothing, the OOS mitigation doesn't appear in the argument

                case _:
                    print(f'invalid scope {mit['scope']}, aborting.')
                    exit(1)

def main(args):
    """
    Generate all the components of the AdvoCATE assurance case skeleton.
    """
    output_path = args.output_path

    # Load data structures from DB; we don't use the contexts here.
    properties, _, mitigations, attacks = get_legacy_data()

    # Add the OOS mitigation, necessary for some of the files.
    augmented_mitigations = mitigations.copy()
    augmented_mitigations['OOS'] = OUT_OF_SCOPE_MITIGATION

    # Generate the functional architecture; this has to happen first because
    # it populates the deviation dictionary.
    functional_architecture_path = \
        os.path.join(output_path, f'{OUTPUT_PREFIX}_FunctionalArchitecture.functionalarchitecture')
    functional_architecture(properties, augmented_mitigations, functional_architecture_path)

    # Generate the safety architecture; this has to happen next because it
    # populates the requirement sources.
    safety_architecture_path = \
        os.path.join(output_path, f'{OUTPUT_PREFIX}_SafetyArchitecture.safetyarch')
    safety_architecture(args.implied, attacks, augmented_mitigations, safety_architecture_path)

    # Generate the requirements log.
    requirements_log_path = \
        os.path.join(output_path, f'{OUTPUT_PREFIX}_Requirements.requirements')
    requirements_log(augmented_mitigations, requirements_log_path)

    # Generate the argument (unless we're told not to).
    if not args.no_argument:
        argument_path = \
            os.path.join(output_path, f'{OUTPUT_PREFIX}_SecurityArgument.argument')
        argument(augmented_mitigations, argument_path)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Generate AdvoCATE skeleton for the E2E-VIV system.')
    parser.add_argument('-i', '--implied', action='store_true', dest='implied',
                        help='Include implied security objectives in safety architecture (off by default).')
    parser.add_argument('-n', '--no-argument', action='store_true', dest='no_argument',
                        help='Do not generate the argument skeleton (it is generated by default).')
    parser.add_argument('output_path', type=str,
                        help="Directory to store the generated skeleton files.")

    main(parser.parse_args())
