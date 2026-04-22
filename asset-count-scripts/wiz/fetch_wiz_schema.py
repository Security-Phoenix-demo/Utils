"""
Fetch Wiz API GraphQL Schema

This script uses GraphQL introspection to fetch and save the Wiz API schema.
This helps us understand what fields are available.
Phoenix-Client Support
"""

import os
import sys
import json
import configparser
import argparse
from pathlib import Path

try:
    import requests
except ImportError:
    print("Error: 'requests' library is not installed.")
    print("\nPlease install it using: pip install requests")
    sys.exit(1)

AUTH_URL = "https://auth.app.wiz.io/oauth/token"
GRAPHQL_URL = "https://api.us10.app.wiz.io/graphql"

def load_credentials():
    """Load credentials from config file, environment variables, or command line"""
    
    # Try to load from config file first
    config_file = Path(__file__).parent / "wiz_config.ini"
    
    if config_file.exists():
        print(f"Loading credentials from {config_file}")
        config = configparser.ConfigParser()
        config.read(config_file)
        
        if "wiz" in config:
            client_id = config["wiz"].get("client_id", "")
            client_secret = config["wiz"].get("client_secret", "")
            
            if client_id and client_secret:
                return client_id, client_secret
    
    # Try environment variables
    client_id = os.environ.get("WIZ_CLIENT_ID", "")
    client_secret = os.environ.get("WIZ_CLIENT_SECRET", "")
    
    if client_id and client_secret:
        print("Loading credentials from environment variables")
        return client_id, client_secret
    
    # Try command line arguments
    parser = argparse.ArgumentParser(description="Wiz Schema Fetcher")
    parser.add_argument("--client-id", help="Wiz Client ID")
    parser.add_argument("--client-secret", help="Wiz Client Secret")
    args = parser.parse_args()
    
    if args.client_id and args.client_secret:
        print("Loading credentials from command line arguments")
        return args.client_id, args.client_secret
    
    # Prompt user for credentials
    print("\nNo credentials found in config file or environment variables.")
    print("Please enter your Wiz API credentials:")
    client_id = input("Client ID: ").strip()
    client_secret = input("Client Secret: ").strip()
    
    if not client_id or not client_secret:
        raise ValueError("Client ID and Client Secret are required")
    
    return client_id, client_secret

def get_token(client_id, client_secret):
    """Get authentication token"""
    headers = {"Content-Type": "application/x-www-form-urlencoded"}

    data = {
        "grant_type": "client_credentials",
        "audience": "beyond-api",
        "client_id": client_id,
        "client_secret": client_secret,
    }

    response = requests.post(AUTH_URL, data=data, headers=headers)

    if response.status_code != 200:
        raise Exception(f"Error when trying to get token: {response.status_code} - {response.text}")

    json_data = response.json()
    return json_data["access_token"]

def fetch_schema(token):
    """Fetch the GraphQL schema using introspection"""
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }

    # GraphQL introspection query
    introspection_query = """
    query IntrospectionQuery {
        __schema {
            queryType { name }
            mutationType { name }
            subscriptionType { name }
            types {
                ...FullType
            }
            directives {
                name
                description
                locations
                args {
                    ...InputValue
                }
            }
        }
    }

    fragment FullType on __Type {
        kind
        name
        description
        fields(includeDeprecated: true) {
            name
            description
            args {
                ...InputValue
            }
            type {
                ...TypeRef
            }
            isDeprecated
            deprecationReason
        }
        inputFields {
            ...InputValue
        }
        interfaces {
            ...TypeRef
        }
        enumValues(includeDeprecated: true) {
            name
            description
            isDeprecated
            deprecationReason
        }
        possibleTypes {
            ...TypeRef
        }
    }

    fragment InputValue on __InputValue {
        name
        description
        type { ...TypeRef }
        defaultValue
    }

    fragment TypeRef on __Type {
        kind
        name
        ofType {
            kind
            name
            ofType {
                kind
                name
                ofType {
                    kind
                    name
                    ofType {
                        kind
                        name
                        ofType {
                            kind
                            name
                            ofType {
                                kind
                                name
                                ofType {
                                    kind
                                    name
                                }
                            }
                        }
                    }
                }
            }
        }
    }
    """

    payload = {
        "query": introspection_query
    }

    response = requests.post(GRAPHQL_URL, json=payload, headers=headers)

    if response.status_code != 200:
        raise Exception(f"Error fetching schema: {response.status_code} - {response.text}")

    return response.json()

def extract_relevant_types(schema_data):
    """Extract and format relevant types from the schema"""
    types = schema_data.get("data", {}).get("__schema", {}).get("types", [])
    
    relevant_types = {}
    
    # Look for types related to cloud resources
    keywords = ["CloudResource", "CloudAccount", "Subscription", "Asset", "Image", "Container"]
    
    for type_info in types:
        type_name = type_info.get("name", "")
        
        # Skip internal GraphQL types
        if type_name.startswith("__"):
            continue
            
        # Check if this type is relevant
        if any(keyword.lower() in type_name.lower() for keyword in keywords):
            relevant_types[type_name] = {
                "kind": type_info.get("kind"),
                "description": type_info.get("description"),
                "fields": []
            }
            
            fields = type_info.get("fields", [])
            if fields:
                for field in fields:
                    relevant_types[type_name]["fields"].append({
                        "name": field.get("name"),
                        "description": field.get("description"),
                        "type": format_type(field.get("type", {}))
                    })
    
    return relevant_types

def format_type(type_ref):
    """Format a type reference into a readable string"""
    if not type_ref:
        return "Unknown"
    
    kind = type_ref.get("kind")
    name = type_ref.get("name")
    
    if kind == "NON_NULL":
        return format_type(type_ref.get("ofType")) + "!"
    elif kind == "LIST":
        return "[" + format_type(type_ref.get("ofType")) + "]"
    elif name:
        return name
    else:
        return format_type(type_ref.get("ofType"))

if __name__ == "__main__":
    try:
        print("Fetching Wiz API GraphQL Schema\n")
        print("=" * 80)
        
        # Load credentials
        client_id, client_secret = load_credentials()
        
        print("\nAuthenticating with Wiz API...")
        token = get_token(client_id, client_secret)
        print("Authentication successful!\n")
        
        print("Fetching GraphQL schema (this may take a moment)...")
        schema = fetch_schema(token)
        
        # Save full schema
        schema_file = Path(__file__).parent / "wiz_graphql_schema_full.json"
        with open(schema_file, 'w') as f:
            json.dump(schema, f, indent=2)
        print(f"✓ Full schema saved to: {schema_file}")
        
        # Extract and save relevant types
        print("\nExtracting relevant types for cloud resources...")
        relevant_types = extract_relevant_types(schema)
        
        relevant_file = Path(__file__).parent / "wiz_graphql_schema_relevant.json"
        with open(relevant_file, 'w') as f:
            json.dump(relevant_types, f, indent=2)
        print(f"✓ Relevant types saved to: {relevant_file}")
        
        # Create a human-readable summary
        summary_file = Path(__file__).parent / "wiz_graphql_schema_summary.txt"
        with open(summary_file, 'w') as f:
            f.write("Wiz API GraphQL Schema - Relevant Types Summary\n")
            f.write("=" * 80 + "\n\n")
            
            for type_name, type_info in sorted(relevant_types.items()):
                f.write(f"\n{type_name} ({type_info['kind']})\n")
                f.write("-" * 80 + "\n")
                if type_info.get("description"):
                    f.write(f"Description: {type_info['description']}\n\n")
                
                f.write("Fields:\n")
                for field in type_info.get("fields", []):
                    f.write(f"  - {field['name']}: {field['type']}\n")
                    if field.get("description"):
                        f.write(f"    {field['description']}\n")
                f.write("\n")
        
        print(f"✓ Human-readable summary saved to: {summary_file}")
        
        print("\n" + "=" * 80)
        print("Schema fetch complete!")
        print("=" * 80)
        print(f"\nFound {len(relevant_types)} relevant types")
        print("\nRelevant types:")
        for type_name in sorted(relevant_types.keys()):
            print(f"  - {type_name}")
        
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)

