#!/usr/bin/env python

# This script parses the threat database YAML into a SQLite3 database file.
# Usage: parse.py [-h] [--dry-run] yaml_file db_file
# --dry-run shows the SQL statements that create the threat model db but does not
# modify the supplied database file
#
# David Ruescas, January 2025
# Copyright (C) 2025 Free & Fair

import argparse
import json
import sqlite3
import sys
import yaml
import os
from jsonschema import validate, exceptions

AUTO_ID = '_'
OUT_OF_SCOPE = "Out of scope"

ATTACK_TABLE = 'ATTACK'
CONTEXT_TABLE = 'CONTEXT'
MITIGATION_TABLE = 'MITIGATION'
PROPERTY_TABLE = 'PROPERTY'

ATTACK_CHILDREN_TABLE = 'ATTACK_CHILDREN'
ATTACK_MITIGATION_TABLE = 'ATTACK_MITIGATION'
PROPERTY_RELATION_TABLE = 'PROPERTY_RELATION'

def sql_quote(value):
    """ Encodes descriptions into suitable sql literals

        :param value: The input text
        :returns: The sql literal value
    """

    if value is None:
        value = 'NULL'
    else:
        # sqlite escapes quotes with two quotes
        value = value.replace("'", "''")
        value = f"""'{value}'"""

    return value

def sql_insert_property(identifier, name, description, parent_fk):
    """ Returns SQL text for a property insert.

        :param identifier: The property identifier, as specified explicitly in the yaml.
        :param name: The property name.
        :param description: The property description
        :param parent_fk: The property subselect SQL text.
        :returns: The SQL text.
    """
    return f"""INSERT INTO PROPERTY (identifier, name, description, kind, parent_fk) VALUES ('{identifier}', '{name}', {sql_quote(description)}, 'Model', {parent_fk});"""

def sql_insert_context(identifier, name, kind, description):
    """ Returns SQL text for a context insert.

        :param identifier: The context identifier, as specified explicitly in the yaml.
        :param name: The context name.
        :param description: The context description.
        :returns: The SQL text.
    """

    return f"""INSERT INTO CONTEXT (identifier, name, kind, description) VALUES ('{identifier}', '{name}', '{kind}', {sql_quote(description)});"""

def sql_insert_attack(attack_dict):
    """ Returns SQL text for an attack insert.

        :param identifier: The attack identifier, usually specified explicitly in the yaml.
        :param name: The attack name.
        :param description: The attack description.
        :returns: The SQL text.
    """
    instance_of = attack_dict['instance_of']
    instance_of_sql = sql_instance_fk(instance_of) if instance_of is not None else 'NULL'
    context = attack_dict['context']
    context_sql = sql_context_fk(context) if context is not None else 'NULL'
    likelihood = 'NULL'
    impact = 'NULL'

    description = attack_dict['description']
    return f"""INSERT INTO ATTACK (identifier, name, description, is_abstract, instanceof_fk, context_fk, likelihood, impact) VALUES (?, '{attack_dict['name']}', {sql_quote(description)}, {attack_dict['is_abstract']}, {instance_of_sql}, {context_sql}, {likelihood}, {impact});"""

def sql_insert_mitigation(identifier, name, description, scope):
    """ Returns SQL text for a mitigation insert.

        :param identifier: The mitigation identifier, as specified explicitly in the yaml.
        :param name: The mitigation name.
        :param description: The mitigation description.
        :param scope: The mitigation scope.
        :returns: The SQL text.
    """
    return f"""INSERT INTO MITIGATION (identifier, name, description, scope) VALUES ('{identifier}', '{name}', {sql_quote(description)}, {sql_quote(scope)});"""

def sql_insert_attack_children():
    """ Returns SQL text for inserting attack parent child relationships.

        SQL parameters will be set by the 'db_insert_with_params' function.

        :returns: The SQL text.
    """
    return """INSERT INTO ATTACK_CHILDREN (parent_fk, child_fk) VALUES (?, ?);"""

def sql_insert_attack_children_ext(parent_fk):
    """ Returns SQL text for inserting attack parent child relationships, with explicit identifiers.

        The SQL parameter for child_fk will be set by the 'db_insert_with_params' function.

        :param parent_fk: The explicit identifier that points to the parent attack.
        :returns: The SQL text.
    """
    return f"""INSERT INTO ATTACK_CHILDREN (parent_fk, child_fk) VALUES ({parent_fk}, ?);"""

def sql_insert_attack_property(property_fk):
    """ Returns SQL text for inserting attack property relationships.

        The SQL parameter for attack_fk will be set by the 'db_insert_with_params' function.

        :param property_fk: The property subselect SQL text.
        :returns: The SQL text.
    """
    return f"""INSERT INTO ATTACK_PROPERTY (attack_fk, property_fk) VALUES (?, {property_fk});"""

def sql_insert_attack_mitigation(mitigation_fk, rationale):
    """ Returns SQL text for inserting attack mitigation relationships.

        The SQL parameter for attack_fk will be set by the 'db_insert_with_params' function.

        :param mitigation_fk: The mitigation subselect SQL text.
        :param rationale: The mitigation rationale, describing how the mitigation applies to the attack.
        :returns: The SQL text.
    """

    return f"""INSERT INTO ATTACK_MITIGATION (attack_fk, mitigation_fk, rationale) VALUES (?, {mitigation_fk}, {sql_quote(rationale)});"""

def sql_subselect_fk(table, value, column='identifier'):
    """ Returns a SQL query used to retrieve a table id for a foreign key value. Fails if not found.

        :param table: The table that the foreign key refers to.
        :param value: The value that will be matched against the supplied column, typically an explicit identifier.
        :param column: The column which identifies the target, typically 'identifier'
        :returns: The subselect SQL text.
    """

    return sql_ifnull(f"SELECT id FROM {table} WHERE {column} = '{value}'")

def sql_ifnull(query):
    """ Wraps a subselect SQL such that it will fail if the target id is not found.

        Used to prevent nullable foreign keys from being accidentally set to null.

        :param query: The input subselect query SQL text.
        :returns: The wrapped subselect query SQL text.
    """
    return f"(SELECT IFNULL(({query}), -1))"

def sql_property_fk(identifier):
    """ Returns a sql query used to retrieve the property id for a foreign key value. Fails if not found.

        :param name: The name of the target property.
        :returns: The subselect SQL text.
    """
    return sql_subselect_fk(PROPERTY_TABLE, identifier)

def sql_attack_fk(identifier):
    """ Returns a sql query used to retrieve the attack id for a foreign key value. Fails if not found.

        :param name: The name of the target attack.
        :returns: The subselect SQL text.
    """
    return sql_subselect_fk(ATTACK_TABLE, identifier)

def sql_context_fk(identifier):
    """ Returns a sql query used to retrieve the context id for a foreign key value. Fails if not found.

        :param name: The name of the target context.
        :returns: The subselect SQL text.
    """

    return sql_subselect_fk(CONTEXT_TABLE, identifier)

def sql_instance_fk(identifier):
    """ Returns a sql query used to retrieve the attack id for an instance_fk foreign key value. Fails if not found.

        :param name: The name of the target abstract attack.
        :returns: The subselect SQL text.
    """

    return sql_ifnull(f"SELECT id FROM ATTACK WHERE identifier = '{identifier}' and is_abstract = 1")

def sql_mitigation_fk(name):
    """ Returns a sql query used to retrieve the mitigation id for a foreign key value. Fails if not found.

        :param name: The name of the target mitigation.
        :returns: The subselect SQL text.
    """

    return sql_subselect_fk(MITIGATION_TABLE, name, 'name')

def generate_property_inserts(yaml_data, parent_fk, inserts = []):
    """ Generates SQL inserts for the given yaml property data tree, recursively.

        :param yaml_data: The section of the yaml data that corresponds to properties.
        :param parent_fk: The property subselect SQL text, passed in from the previous recursion level.
        :param inserts: Inserts accumulated in previous levels of recursion.
        :returns: The list of SQL inserts.
    """
    for identifier, values in with_context(yaml_data.items()):
        name = identifier
        if isinstance(values, str):
            inserts.append(sql_insert_property(identifier, name, values, parent_fk))
        elif isinstance(values, list):
            inserts.append(sql_insert_property(identifier, name, values[0], parent_fk))
            generate_property_inserts(values[1], sql_property_fk(name), inserts)

    return inserts

def generate_context_inserts(yaml_data):
    """ Generates SQL inserts for the given yaml context data.

        :param yaml_data: The section of the yaml data that corresponds to contexts.
        :returns: The list of SQL inserts.
    """

    inserts = []

    for identifier, values in yaml_data.items():
        name, kind, description = (list(values) + [None]*3)[:3]
        inserts.append(sql_insert_context(identifier, name, kind, description))
    return inserts

def generate_attack_inserts(yaml_data, is_child=False):
    """ Generates SQL inserts for the given yaml attack data tree, recursively.

        The input yaml data hierarchy encodes parent child relations as well as attack mitigation relations.
        This hierarchy only supports single parents. However, there is a mechanism to specify additional
        parents explicitly (as opposed to implicit in the yaml data hierarchy) by identifier.

        Other relations encoded explicitly:

        Context: by identifier
        Instance: by identifier

        :param yaml_data: The section of the yaml data that corresponds to attacks and related mitigations.
        :param is_child: Whether the current recursion requires linking to its parent attack
        :returns: Returns derived inserts data with the following structure:

        return = [{
            'self_inserts': attack_map,
            'children': attack_children
        }]

        attack_map = {
            'context': context_attack
        }

        context_attack = {
            'context': context identifier,
            'attack_dict': attack_dict,
            'parent_inserts': [sql to set this attack's parents]
            'mitigation_inserts': [sql to set this attack's mitigations]
        }

        attack_dict = {
            'identifier': attack identifier,
            'name': name, attack name
            'description': attack description,
            'is_abstract': is_abstract ,
            'instance_of': instance attack (dict),
            'context': target context (dict)
        }

        attack_children: RECURSE
    """

    all_inserts = []
    a_count = 0
    m_count = 0

    for item in with_context(yaml_data):

        attack_children = []

        keys = list(item.keys())

        if 'children' in keys:
            attack_children, ac, mc = generate_attack_inserts(item['children'], True)
            a_count += ac
            m_count += mc
            keys.remove('children')

        if 'mitigations' in keys:
            keys.remove('mitigations')

        if AUTO_ID in keys:
            attack = item[AUTO_ID]
            identifier = None
        else:
            # explicit id
            identifier = keys[0]
            attack = item[identifier]

        attack_type = attack['kind'] if 'kind' in attack else 'S'
        name = attack['name']
        properties = attack['properties'] if 'properties' in attack else None
        description = attack['description'] if 'description' in attack else None
        instance_of = attack['instance_of'] if 'instance_of' in attack else None
        contexts = attack['contexts'] if 'contexts' in attack else None
        additional_parents = attack['parents'] if 'parents' in attack else None

        is_abstract = 1 if attack_type == 'A' else 0

        if properties is not None:
            properties = properties if type(properties) is list else [properties]
        property_fks = [sql_property_fk(prop) for prop in properties] if properties is not None else []

        attack_map = {}

        # If there are no contexts, the attack context will be set to NULL
        if not contexts:
            contexts = [None]

        for context in contexts:

            context_attack = { 'context': context }
            context_attack['attack_dict'] = attack_dict(identifier, name, description, is_abstract, instance_of, context)
            a_count += 1

            parent_inserts = []
            if is_child:
                parent_inserts.append(sql_insert_attack_children())

            # support for additional parents through explicit identifiers
            if additional_parents is not None and len(additional_parents) > 0:
                for parent in additional_parents if type(additional_parents) is list else [additional_parents]:
                    parent_inserts.append(sql_insert_attack_children_ext(sql_attack_fk(parent)))

            context_attack['parent_inserts'] = parent_inserts

            property_inserts = []
            for property_fk in property_fks:
                property_inserts.append(sql_insert_attack_property(property_fk))
            context_attack['property_inserts'] = property_inserts

            attack_map[context] = context_attack

        for mitigation in item['mitigations'] if 'mitigations' in item else []:

            mit, m_context, rationale = (list(mitigation) + [None]*3)[:3]

            if mit == OUT_OF_SCOPE:
                mit = None
            mitigation_fk = sql_mitigation_fk(mit) if mit is not None else 'NULL'

            # If the context is not specified, it is interpreted as all contexts (if any)
            if len(mitigation) == 2:
                rationale = m_context
                m_context = contexts

            mit = sql_insert_attack_mitigation(mitigation_fk, rationale)

            for ctx in m_context if isinstance(m_context, list) else [m_context]:
                if 'mitigation_inserts' not in attack_map[ctx]:
                    attack_map[ctx]['mitigation_inserts'] = [mit]
                else:
                    attack_map[ctx]['mitigation_inserts'].append(mit)

                m_count += 1

        all_inserts.append({'self_inserts': attack_map, 'children_inserts': attack_children})

    return all_inserts, a_count, m_count

def generate_mitigation_inserts(yaml_data, inserts = []):
    """ Generates SQL inserts for the given yaml mitigation data.

        :param yaml_data: The section of the yaml data that corresponds to mitigations.
        :returns: The list of SQL inserts.
    """

    for identifier, mitigation in yaml_data.items():
        name, description, scope = mitigation
        inserts.append(sql_insert_mitigation(identifier, name, description, scope))

    return inserts, len(yaml_data)

def generate_flat_property_inserts(yaml_data):
    """ Generates SQL inserts for the given yaml property data.

        :param yaml_data: The section of the yaml data that corresponds to flat properties.
        :returns: The list of SQL inserts.
    """

    inserts = []
    for identifier, values in yaml_data.items():
        name, related_properties = values
        inserts.append(f"INSERT INTO PROPERTY (identifier, name, kind) VALUES ('{identifier}', '{name}', 'E-voting');")
        for related_property in related_properties:
            inserts.append(f"INSERT INTO PROPERTY_RELATION (left_fk, right_fk) VALUES ((SELECT id FROM PROPERTY WHERE identifier='{identifier}'), (SELECT id FROM PROPERTY WHERE identifier='{related_property}'));")
    return inserts

def db_init(db_file_path):
    """ Drops and creates the schema tables.

        :param db_file_path: The filesystem path to the database file.
    """

    conn = sqlite3.connect(db_file_path)
    conn.execute("drop table if exists `IDENTIFIER`;")
    conn.execute("drop table if exists `PROPERTY`;")
    conn.execute("drop table if exists `PROPERTY_RELATION`;")
    conn.execute("drop table if exists `CONTEXT`;")
    conn.execute("drop table if exists `MITIGATION`;")
    conn.execute("drop table if exists `ATTACK`;")
    conn.execute("drop table if exists `ATTACK_PROPERTY`;")
    conn.execute("drop table if exists `ATTACK_MITIGATION`;")
    conn.execute("drop table if exists `ATTACK_CHILDREN`;")
    conn.execute("""CREATE TABLE IF NOT EXISTS "PROPERTY" (`id` INTEGER PRIMARY KEY AUTOINCREMENT, `identifier` TEXT UNIQUE NOT NULL, `name` TEXT UNIQUE NOT NULL, `description` TEXT, `kind` TEXT CHECK(kind in ('Model', 'E-voting', 'Stride')), `parent_fk` INTEGER, FOREIGN KEY(parent_fk) REFERENCES `PROPERTY`(id));""")
    conn.execute("""CREATE TABLE `PROPERTY_RELATION` (`left_fk` INTEGER NOT NULL REFERENCES `PROPERTY`(`id`), `right_fk` INTEGER NOT NULL REFERENCES `PROPERTY`(`id`));""")
    conn.execute("""CREATE TABLE IF NOT EXISTS "CONTEXT" (`id` INTEGER PRIMARY KEY AUTOINCREMENT, `identifier` TEXT UNIQUE NOT NULL, `name` TEXT UNIQUE NOT NULL, kind TEXT NOT NULL CHECK (kind in ('Subsystem', 'Network', 'Actor', 'Primitive', 'Data')), description TEXT, scope TEXT);""")
    conn.execute("""CREATE TABLE IF NOT EXISTS "MITIGATION" (`id` INTEGER PRIMARY KEY AUTOINCREMENT, `identifier` TEXT UNIQUE NOT NULL, `name` TEXT NOT NULL, description TEXT, scope TEXT NOT NULL CHECK (scope in ('core', 'non-core', 'partially-core')));""")
    conn.execute("""CREATE TABLE `ATTACK_PROPERTY` (`attack_fk` INTEGER NOT NULL REFERENCES `ATTACK`(`id`), `property_fk` INTEGER NOT NULL REFERENCES `PROPERTY`(`id`));""")
    conn.execute("""CREATE TABLE IF NOT EXISTS "ATTACK_MITIGATION" (`attack_fk` INTEGER NOT NULL REFERENCES `ATTACK`(`id`), `mitigation_fk` INTEGER REFERENCES `MITIGATION`(`id`), `rationale` TEXT, PRIMARY KEY(attack_fk, mitigation_fk));""")
    conn.execute("""CREATE TABLE `ATTACK_CHILDREN` (`parent_fk` INTEGER NOT NULL REFERENCES `ATTACK`(`id`), `child_fk` INTEGER NOT NULL REFERENCES `ATTACK`(`id`), PRIMARY KEY(parent_fk, child_fk));""")
    conn.execute("""CREATE TABLE IF NOT EXISTS "ATTACK" (`id` INTEGER PRIMARY KEY AUTOINCREMENT, `identifier` TEXT UNIQUE NOT NULL, `name` TEXT NOT NULL, `description` TEXT, `is_abstract` INTEGER NOT NULL CHECK(is_abstract in (0, 1)), `instanceof_fk` INTEGER, `context_fk` INTEGER, `likelihood` TEXT, `impact` TEXT, FOREIGN KEY(instanceof_fk) REFERENCES `ATTACK`(id), FOREIGN KEY(context_fk) REFERENCES `CONTEXT`(id));""")
    conn.commit()
    conn.close()

def db_insert(db_file_path, inserts, dry_run=False, debug=False):
    """ Executes the supplied SQL inserts.

        If an exception is thrown, this function will print the insert that caused it.

        :param db_file_path: The filesystem path to the database file.
        :param inserts: The SQL inserts to execute
        :param dry_run: If True will only print but not execute inserts.
        :param debug: If True will print inserts before executing them.
    """

    if dry_run:
        for insert in inserts:
            print(insert)
        return

    conn = sqlite3.connect(db_file_path)
    conn.execute("PRAGMA foreign_keys = ON;")
    cursor = conn.cursor()
    for insert in inserts:
        try:
            if debug:
                print(insert)
            cursor.execute(insert)
        except sqlite3.Error as er:
            print(f"{er} caused by: '{insert}'")
            raise er

    conn.commit()
    conn.close()

def db_insert_attack_tree(db_file_path, attack_roots, dry_run=False):
    """ Execute SQL inserts for a list of attack tree roots.

        :param db_file_path: The filesystem path to the database file.
        :param attack_roots: The insert data for root attacks, as defined in the 'generate_attack_inserts' function.
        :param dry_run: If True will only print but not execute inserts.
    """

    conn = sqlite3.connect(db_file_path)
    conn.execute("PRAGMA foreign_keys = ON;")
    cursor = conn.cursor()

    for root in attack_roots:
        db_insert_attack_root(root, cursor, parent_dict=None, dry_run=dry_run)

    conn.commit()
    conn.close()

def db_insert_attack_root(inserts, cursor, parent_dict=None, dry_run=False):
    """ Execute SQL inserts for an attack tree root.

        :param inserts: The insert data for an attack, as defined in the 'generate_attack_inserts' function.
        :param cursor: The database cursor.
        :param parent_dict: The dictionary with the parent attack data, it will always be a parent without context.
            An alternate implementation could add a child per context, but this does not seem to model anything meaningful.
        :param dry_run: If True will only print but not execute inserts.
    """

    attack_dicts = {}

    self_inserts = inserts['self_inserts']
    for context, values in self_inserts.items():

        ad = values['attack_dict']

        # identifiers are of form Parent.Child.Context
        parent_string = ''
        context_string = ''
        parent_id = None
        if parent_dict:
            parent_string = f"{parent_dict['name']}."
            parent_id = parent_dict['id']
        context_string = f".{ad['context']}" if ad['context'] is not None else ''

        if ad['identifier'] is None:
            identifier = f"{parent_string}{ad['name']}{context_string}"
        else:
            identifier = ad['identifier']

        attack_insert = sql_insert_attack(ad)
        row_id = db_insert_with_params(attack_insert, cursor, (identifier,), dry_run)
        # set the id for passing the parent dict down
        ad['id'] = row_id
        attack_dicts[context] = ad

        property_inserts = values['property_inserts']
        for pi in property_inserts:
            db_insert_with_params(pi, cursor, (row_id,), dry_run)

        parent_inserts = values['parent_inserts']
        for pi in parent_inserts:
            # hack to support additional parents
            if "VALUES (?, ?);" in pi:
                db_insert_with_params(pi, cursor, (parent_id, row_id), dry_run)
            else:
                db_insert_with_params(pi, cursor, (row_id,), dry_run)

        if 'mitigation_inserts' in values:
            for mi in values['mitigation_inserts']:
                db_insert_with_params(mi, cursor, (row_id,), dry_run)


    pc_inserts = inserts['children_inserts']
    for pc in pc_inserts:
        # the child is only added to context = None, attacks with contexts do not generate children
        db_insert_attack_root(pc, cursor, attack_dicts[None], dry_run)

def db_insert_with_params(insert, cursor, params, dry_run=False):
    """ Executes on SQL insert, with parameters.

        If an exception is thrown, this function will print the insert.

        :param insert: The SQL insert text.
        :param cursor: The database cursor.
        :param params: The parameter values to set for SQL value placeholders (?)
        :param debug: If True will print inserts before executing them.
    """

    try:
        if dry_run:
            print(f"{insert}, params = {params}")
        else:
            cursor.execute(insert, params)
            return cursor.lastrowid

    except sqlite3.Error as er:
        print(f"*** {er} caused by: '{insert}'")
        raise er

def main():
    parser = argparse.ArgumentParser(description='Parse YAML file and insert into DB (will be wiped).')
    parser.add_argument('yaml_file', type=str, help='Path to the YAML file')
    parser.add_argument('db_file', type=str, help='Path to the SQLite database file')
    parser.add_argument('--dry-run', action='store_true', help='Print the derived insert statements without executing them')
    args = parser.parse_args()

    if not os.path.exists(args.yaml_file):
        abort(f"Could not find yaml file '{args.yaml_file}'")

    yaml_file_path = args.yaml_file
    db_file_path = args.db_file

    try:
        conn = sqlite3.connect(db_file_path)
        conn.execute("PRAGMA integrity_check;")
    except sqlite3.Error as er:
        abort(f"File '{args.db_file}' is not a sqlite3 database")

    # Read the YAML file
    yaml_data = read_yaml(yaml_file_path)

    if not args.dry_run:
        db_init(db_file_path)
        print("*** Cleared database ***")

    # Generate SQL insert statements for properties
    property_inserts = generate_property_inserts(yaml_data.get('properties', {}), 'NULL')
    db_insert(db_file_path, property_inserts, args.dry_run)

    # Generate SQL insert statements for contexts
    context_inserts = generate_context_inserts(yaml_data.get('contexts', []))
    db_insert(db_file_path, context_inserts, args.dry_run)

    # Generate SQL insert statements for mitigations
    mitigation_inserts, m_count = generate_mitigation_inserts(yaml_data.get('mitigations', []))
    db_insert(db_file_path, mitigation_inserts, args.dry_run)

    # Generate SQL insert statements for attacks
    attack_inserts, a_count, am_count = generate_attack_inserts(yaml_data.get('attacks', []))
    db_insert_attack_tree(db_file_path, attack_inserts, args.dry_run)

    # Generate SQL insert statements for stride
    stride_inserts = generate_flat_property_inserts(yaml_data.get('stride', []))
    db_insert(db_file_path, stride_inserts, args.dry_run)

    # Generate SQL insert statements for e-voting
    evoting_inserts = generate_flat_property_inserts(yaml_data.get('e-voting', []))
    db_insert(db_file_path, evoting_inserts, args.dry_run)

    print("Inserts:")
    print(f"{len(property_inserts)} properties")
    print(f"{len(context_inserts)} contexts")
    print(f"{a_count} attacks")
    print(f"{m_count} mitigations ({am_count} applied)")

def read_yaml(file_path):
    """ Read a yaml file

        :param file_path: The filesystem path to the yaml file.
        :returns: Python data structures representing the yaml content.
    """
    with open(file_path, 'r') as file:
        data = yaml.safe_load(file)
        try:
            schema = load_json_schema()
            validate(data, schema)
        except exceptions.ValidationError as err:
            abort(f"Yaml file '{file_path}' failed to validate:{err}")

        return data

def load_json_schema():
    """ Loads the JSON schema from the external schema file.

        The schema file is expected to be in the same directory as this script,
        named 'threat-model-schema.json'.

        :returns: The json schema.
    """
    script_dir = os.path.dirname(os.path.abspath(__file__))
    schema_path = os.path.join(script_dir, 'threat-model-schema.json')

    if not os.path.exists(schema_path):
        abort(f"Could not find schema file '{schema_path}'")

    with open(schema_path, 'r') as schema_file:
        return json.load(schema_file)

def attack_dict(identifier, name, description, is_abstract, instance_of, context):
    """ Returns a python dict representing an attack.

        :param identifier: Attack identifier.
        :param name: Attack name.
        :param description: Attack description.
        :param is_abstract: Is the attack abstract.
        :param instance_of: The abstract attack (dict) this is an instance of.
        :param context: The context (dict) for this attack
        :returns:
    """
    return {'identifier': identifier, 'name': name, 'description': description, 'is_abstract': is_abstract, 'instance_of': instance_of, 'context': context}

def with_context(iter):
    """ Returns a LoopContext object that can be used to iterate over a yaml object with context.

        :param iter: The yaml object to iterate over.
        :returns: The LoopContext
    """
    return LoopContext(iter)

def loop_except_hook(exctype, value, traceback):
    """ Prints yaml context information when throwing exceptions.

        :param exctype: The exception type.
        :param value: The exception value.
        :param traceback: The traceback.
    """
    sys.__excepthook__(exctype, value, traceback)
    try:
        if loop_context is not None:
            print("\nYaml = ")
            print(json.dumps(loop_context, indent = 2))
    except NameError:
        # we don't care
        pass

class LoopContext:
  def __init__(self, yaml):
    """ Stores the yaml context.

        :param yaml: The yaml object to iterate over.
    """
    self.yaml = iter(yaml)

  def __iter__(self):
    """ Returns this iterator.

        :returns: This iterator.
    """
    return self

  def __next__(self):
    """ Returns the next element in the iteration, while setting the context.

        :returns: The next element in the iteration.
    """
    global loop_context
    n = next(self.yaml, None)
    loop_context = n
    if n is None:
        raise StopIteration
    else:
        return n

def abort(message):
    """ Prints an error message and exits the program.

        :param message: The error message.
    """
    print(message)
    sys.exit(1)

if __name__ == "__main__":
    sys.excepthook = loop_except_hook
    main()
