import argparse
import yaml
import json
import shutil
from pathlib import Path

SCHEMA_FILE = "threat-model-schema.json"
SCHEMA_BACKUP = "threat-model-schema.base.json"
SCHEMA_ENHANCED = "threat-model-schema-enhanced.json"


def read_yaml(file_path):
    with open(file_path, 'r') as file:
        return yaml.safe_load(file)


def read_json(file_path):
    with open(file_path) as f:
        return json.load(f)


def write_json(file_path, data):
    with open(file_path, 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=2)


def get_properties(yaml_data, prefix=""):
    """Recursively extract all property identifiers (leaf IDs only, not full paths)"""
    ret = []
    for identifier, values in yaml_data.items():
        # Add just the identifier itself (not the full path)
        ret.append(identifier)

        if isinstance(values, list) and len(values) >= 2 and isinstance(values[1], dict):
            # Has children - recurse without building full path
            ret.extend(get_properties(values[1], ""))

    return ret


def get_contexts(yaml_data):
    """Extract all context identifiers"""
    return list(yaml_data.keys())


def get_mitigations(yaml_data):
    """Extract all mitigation names (not IDs, since attacks reference by name)"""
    names = [values[0] for values in yaml_data.values()]  # First element is the name
    # Add special "Out of scope" value that can be used in attacks
    names.append("Out of scope")
    return names


def enhance_schema_with_enums(base_schema, property_ids, context_ids, mitigation_ids):
    """
    Add enum constraints to the schema for cross-references.
    This creates dynamic autocomplete based on file contents.
    """
    schema = json.loads(json.dumps(base_schema))  # Deep copy

    # Add context enum to attack schema
    if "$defs" in schema and "attack" in schema["$defs"]:
        attack_def = schema["$defs"]["attack"]
        if "properties" in attack_def and "_" in attack_def["properties"]:
            attack_props = attack_def["properties"]["_"]["properties"]

            # Add enum for contexts array
            if "contexts" in attack_props:
                if attack_props["contexts"].get("type") == "array":
                    attack_props["contexts"]["items"] = {
                        "type": "string",
                        "enum": sorted(context_ids),
                        "description": "Context identifier (auto-generated from contexts section)"
                    }

            # Add enum for properties array
            if "properties" in attack_props:
                if attack_props["properties"].get("type") == "array":
                    attack_props["properties"]["items"] = {
                        "type": "string",
                        "enum": sorted(property_ids),
                        "description": "Property identifier (auto-generated from properties section)"
                    }

        # Add enum for mitigation first element (mitigation name reference)
        if "properties" in attack_def and "mitigations" in attack_def["properties"]:
            if "items" in attack_def["properties"]["mitigations"]:
                mitigation_items = attack_def["properties"]["mitigations"]["items"]
                # The mitigation array is [mitigation_name, rationale] or [mitigation_name, context, rationale]
                mitigation_items["items"] = [
                    {
                        "type": "string",
                        "enum": sorted(mitigation_ids),
                        "description": "Mitigation name (auto-generated from mitigations section)"
                    },
                    {
                        "type": "string",
                        "description": "Rationale or context"
                    },
                    {
                        "type": "string",
                        "description": "Rationale (if context was provided as second element)"
                    }
                ]
                mitigation_items["additionalItems"] = False

    return schema


def main():
    try:
        parser = argparse.ArgumentParser(
            description='Generate enhanced JSON Schema with autocomplete enums from YAML threat model'
        )
        parser.add_argument('yaml_file', type=str, help='Path to the YAML threat model file')
        args = parser.parse_args()

        # Create backup of original schema on first run
        schema_path = Path(SCHEMA_FILE)
        backup_path = Path(SCHEMA_BACKUP)

        if schema_path.exists() and not backup_path.exists():
            print(f"Creating backup: {SCHEMA_BACKUP}")
            shutil.copy2(schema_path, backup_path)

        # Read base schema
        base_schema = read_json(SCHEMA_FILE)

        # Read YAML threat model
        yaml_data = read_yaml(args.yaml_file)

        # Extract identifiers
        property_ids = get_properties(yaml_data.get('properties', {}))
        context_ids = get_contexts(yaml_data.get('contexts', {}))
        mitigation_ids = get_mitigations(yaml_data.get('mitigations', {}))

        print(f"Extracted {len(property_ids)} properties, {len(context_ids)} contexts, {len(mitigation_ids)} mitigations")

        # Generate enhanced schema with enums
        enhanced_schema = enhance_schema_with_enums(
            base_schema,
            property_ids,
            context_ids,
            mitigation_ids
        )

        # Write enhanced schema
        write_json(SCHEMA_ENHANCED, enhanced_schema)
        print(f"Generated {SCHEMA_ENHANCED}")

        # Update the main schema file to point to enhanced version
        # This allows the YAML Language Server to pick up the changes
        write_json(SCHEMA_FILE, enhanced_schema)
        print(f"Updated {SCHEMA_FILE} with enhanced schema")

    except Exception as e:
        print(f"generate_schema.py error: {e}")
        import traceback
        traceback.print_exc()
        exit(1)


if __name__ == "__main__":
    main()
