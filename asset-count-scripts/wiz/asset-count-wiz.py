"""
Wiz Asset Count Script

This script fetches cloud resources from Wiz API and groups them by cloud account.
It exports the data to both JSON and CSV formats with timestamps.

Dependencies:
    - requests (install via: pip install -r requirements.txt)

Usage:
    # Normal mode - fetches all resources
    python asset-count-wiz.py
    
    # Test mode - fetches only 500 resources for testing
    python asset-count-wiz.py --test-mode
    
    # With credentials
    python asset-count-wiz.py --client-id YOUR_ID --client-secret YOUR_SECRET
    python asset-count-wiz.py --client-id YOUR_ID --client-secret YOUR_SECRET --test-mode

Output:
    - JSON file: wiz_assets_YYYYMMDD_HHMMSS.json
    - CSV file: wiz_assets_YYYYMMDD_HHMMSS.csv

For more information, see README.md
"""

import os
import sys
import configparser
import argparse
import json
import csv
from datetime import datetime
from pathlib import Path

# Check if requests library is installed
try:
    import requests
except ImportError:
    print("Error: 'requests' library is not installed.")
    print("\nPlease install it using one of the following methods:")
    print("  1. pip install -r requirements.txt")
    print("  2. pip install requests")
    sys.exit(1)

AUTH_URL = "https://auth.app.wiz.io/oauth/token"
GRAPHQL_URL = "https://api.us10.app.wiz.io/graphql"

def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(description="Wiz Asset Count Script")
    parser.add_argument("--client-id", help="Wiz Client ID")
    parser.add_argument("--client-secret", help="Wiz Client Secret")
    parser.add_argument("--test-mode", action="store_true", help="Test mode: fetch only 500 resources")
    return parser.parse_args()

def load_credentials(args=None):
    """Load credentials from config file, environment variables, or command line"""
    
    if args is None:
        args = parse_arguments()
    
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
                return client_id, client_secret, args.test_mode
    
    # Try environment variables
    client_id = os.environ.get("WIZ_CLIENT_ID", "")
    client_secret = os.environ.get("WIZ_CLIENT_SECRET", "")
    
    if client_id and client_secret:
        print("Loading credentials from environment variables")
        return client_id, client_secret, args.test_mode
    
    # Try command line arguments
    if args.client_id and args.client_secret:
        print("Loading credentials from command line arguments")
        return args.client_id, args.client_secret, args.test_mode
    
    # Prompt user for credentials
    print("\nNo credentials found in config file or environment variables.")
    print("Please enter your Wiz API credentials:")
    client_id = input("Client ID: ").strip()
    client_secret = input("Client Secret: ").strip()
    
    if not client_id or not client_secret:
        raise ValueError("Client ID and Client Secret are required")
    
    return client_id, client_secret, args.test_mode

def get_token(client_id, client_secret):
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

def get_cloud_resources_by_account(token, test_mode=False):
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }

    query = """
    query CloudResourcesPaginated($filterBy: CloudResourceFilters, $first: Int, $after: String) {
        cloudResources(filterBy: $filterBy, first: $first, after: $after) {
            totalCount
            pageInfo {
                hasNextPage
                endCursor
            }
            nodes {
                id
                name
                type
                nativeType
                subscriptionId
                subscriptionName
                subscriptionExternalId
            }
        }
    }
    """

    all_resources = []
    has_next_page = True
    after_cursor = None
    page_size = 500  # Fetch 500 resources at a time
    test_limit = 500  # In test mode, fetch only 500 resources

    if test_mode:
        print("⚠️  TEST MODE ENABLED: Fetching only 500 resources for testing\n")

    while has_next_page:
        payload = {
            "query": query,
            "variables": {
                "filterBy": {},
                "first": page_size,
                "after": after_cursor
            }
        }

        response = requests.post(GRAPHQL_URL, json=payload, headers=headers)

        if response.status_code != 200:
            raise Exception(f"Error in get_cloud_resources_by_account(): {response.status_code} - {response.text}")

        data = response.json()
        cloud_resources = data.get("data", {}).get("cloudResources", {})
        
        nodes = cloud_resources.get("nodes", [])
        all_resources.extend(nodes)
        
        page_info = cloud_resources.get("pageInfo", {})
        has_next_page = page_info.get("hasNextPage", False)
        after_cursor = page_info.get("endCursor")
        
        print(f"Fetched {len(all_resources)} resources so far...")
        
        # Break early in test mode
        if test_mode and len(all_resources) >= test_limit:
            print(f"Test mode limit reached ({test_limit} resources)")
            has_next_page = False

    return {
        "totalCount": cloud_resources.get("totalCount", len(all_resources)),
        "resources": all_resources
    }

def get_subscriptions(token):
    """Fetch all subscriptions to map subscription IDs to names and providers"""
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }

    query = """
    query Subscriptions($first: Int, $after: String) {
        cloudAccounts(first: $first, after: $after) {
            pageInfo {
                hasNextPage
                endCursor
            }
            nodes {
                id
                name
                externalId
                cloudProvider
            }
        }
    }
    """

    all_subscriptions = {}
    has_next_page = True
    after_cursor = None
    page_size = 500

    print("Fetching cloud account/subscription information...")
    
    while has_next_page:
        payload = {
            "query": query,
            "variables": {
                "first": page_size,
                "after": after_cursor
            }
        }

        response = requests.post(GRAPHQL_URL, json=payload, headers=headers)

        if response.status_code != 200:
            # If this fails, return empty dict and we'll group by subscription ID only
            print(f"Warning: Could not fetch subscription details: {response.status_code}")
            return {}

        data = response.json()
        accounts = data.get("data", {}).get("cloudAccounts", {})
        
        nodes = accounts.get("nodes", [])
        for account in nodes:
            all_subscriptions[account["id"]] = {
                "name": account.get("name", "Unknown"),
                "externalId": account.get("externalId", "Unknown"),
                "cloudProvider": account.get("cloudProvider", "Unknown")
            }
        
        page_info = accounts.get("pageInfo", {})
        has_next_page = page_info.get("hasNextPage", False)
        after_cursor = page_info.get("endCursor")

    print(f"Fetched {len(all_subscriptions)} cloud accounts/subscriptions")
    return all_subscriptions

def get_discovered_images_count(token):
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }

    query = """
    query DiscoveredImageSearch($query: GraphEntityQueryInput, $first: Int) {
        graphSearch(query: $query, first: $first) {
            totalCount
        }
    }
    """

    variables = {
        "first": 1,
        "query": {
            "type": "CONTAINER_IMAGE",
            "where": {
                "subscriptionExternalId": {
                    "IS_SET": False
                }
            }
        }
    }

    payload = {
        "query": query,
        "variables": variables
    }

    response = requests.post(GRAPHQL_URL, json=payload, headers=headers)

    if response.status_code != 200:
        raise Exception(f"Error en GraphQL (DiscoveredImageSearch): {response.status_code} - {response.text}")

    return response.json()

def group_resources_by_account(resources, subscriptions):
    """Group resources by cloud account"""
    grouped = {}
    
    for resource in resources:
        # Try to get subscription info directly from resource first
        subscription_name = resource.get("subscriptionName")
        subscription_external_id = resource.get("subscriptionExternalId")
        subscription_id = resource.get("subscriptionId")
        
        # If we have the basic info from the resource itself, use it
        if subscription_name and subscription_external_id:
            # Get cloud provider from the subscriptions mapping if available
            cloud_provider = "Unknown"
            if subscription_id and subscription_id in subscriptions:
                cloud_provider = subscriptions[subscription_id].get("cloudProvider", "Unknown")
            
            key = f"{cloud_provider}:{subscription_name} ({subscription_external_id})"
        elif subscription_id and subscription_id in subscriptions:
            # Fall back to subscription mapping
            sub_info = subscriptions[subscription_id]
            account_name = sub_info.get("name", "Unknown")
            account_id = sub_info.get("externalId", "Unknown")
            cloud_provider = sub_info.get("cloudProvider", "Unknown")
            key = f"{cloud_provider}:{account_name} ({account_id})"
        elif subscription_id:
            key = f"Unknown Account ({subscription_id})"
        else:
            key = "No Subscription"
        
        if key not in grouped:
            grouped[key] = []
        
        grouped[key].append(resource)
    
    return grouped

def export_to_json(grouped_resources, total_count, discovered_images_count, output_path):
    """Export asset data to JSON format"""
    
    accounts_data = []
    
    for account_key, account_resources in grouped_resources.items():
        # Parse account info from key
        cloud_provider = "Unknown"
        account_name = "Unknown"
        account_id = "Unknown"
        
        if ":" in account_key:
            cloud_provider, rest = account_key.split(":", 1)
            if "(" in rest and ")" in rest:
                account_name = rest[:rest.rfind("(")].strip()
                account_id = rest[rest.rfind("(")+1:rest.rfind(")")]
            else:
                account_name = rest
        else:
            account_name = account_key
        
        # Count resource types
        resource_types = {}
        for res in account_resources:
            res_type = res.get("type", "Unknown")
            resource_types[res_type] = resource_types.get(res_type, 0) + 1
        
        # Build resource type list
        resource_type_list = [
            {"type": res_type, "count": count}
            for res_type, count in sorted(resource_types.items(), key=lambda x: x[1], reverse=True)
        ]
        
        accounts_data.append({
            "cloud_provider": cloud_provider,
            "account_name": account_name,
            "account_id": account_id,
            "total_resources": len(account_resources),
            "resource_types": resource_type_list
        })
    
    # Sort by total resources
    accounts_data.sort(key=lambda x: x["total_resources"], reverse=True)
    
    output = {
        "export_timestamp": datetime.now().isoformat(),
        "summary": {
            "total_cloud_accounts": len(grouped_resources),
            "total_cloud_resources": total_count,
            "discovered_images_unlinked": discovered_images_count,
            "grand_total_assets": total_count + discovered_images_count
        },
        "accounts": accounts_data
    }
    
    with open(output_path, 'w') as f:
        json.dump(output, f, indent=2)
    
    print(f"\n✅ JSON export saved to: {output_path}")
    return output_path

def export_to_csv(grouped_resources, output_path):
    """Export asset data to CSV format"""
    
    rows = []
    
    for account_key, account_resources in grouped_resources.items():
        # Parse account info from key
        cloud_provider = "Unknown"
        account_name = "Unknown"
        account_id = "Unknown"
        
        if ":" in account_key:
            cloud_provider, rest = account_key.split(":", 1)
            if "(" in rest and ")" in rest:
                account_name = rest[:rest.rfind("(")].strip()
                account_id = rest[rest.rfind("(")+1:rest.rfind(")")]
            else:
                account_name = rest
        else:
            account_name = account_key
        
        # Count resource types
        resource_types = {}
        for res in account_resources:
            res_type = res.get("type", "Unknown")
            resource_types[res_type] = resource_types.get(res_type, 0) + 1
        
        # Create a row for each resource type
        for res_type, count in sorted(resource_types.items(), key=lambda x: x[1], reverse=True):
            rows.append({
                "cloud_provider": cloud_provider,
                "account_name": account_name,
                "account_id": account_id,
                "resource_type": res_type,
                "count": count,
                "account_total_resources": len(account_resources)
            })
    
    # Sort by account total resources, then by count
    rows.sort(key=lambda x: (x["account_total_resources"], x["count"]), reverse=True)
    
    with open(output_path, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=[
            "cloud_provider", "account_name", "account_id", 
            "resource_type", "count", "account_total_resources"
        ])
        writer.writeheader()
        writer.writerows(rows)
    
    print(f"✅ CSV export saved to: {output_path}")
    return output_path

if __name__ == "__main__":
    try:
        # Parse arguments and load credentials
        args = parse_arguments()
        client_id, client_secret, test_mode = load_credentials(args)
        
        print("\nAuthenticating with Wiz API...")
        token = get_token(client_id, client_secret)
        print("Authentication successful!\n")
        
        # Fetch subscription/account information first
        subscriptions = get_subscriptions(token)
        print()
        
        print("Fetching cloud resources...")
        cloud_resources_data = get_cloud_resources_by_account(token, test_mode=test_mode)
        total_count = cloud_resources_data["totalCount"]
        resources = cloud_resources_data["resources"]
        
        print(f"\n{'=' * 80}")
        print(f"TOTAL ASSET COUNT: {total_count}")
        if test_mode:
            print(f"(Test mode - fetched only {len(resources)} resources)")
        print(f"{'=' * 80}")
        
        print("\nGrouping assets by cloud account...\n")
        
        grouped_resources = group_resources_by_account(resources, subscriptions)
        
        print("=" * 80)
        print("ASSETS GROUPED BY CLOUD ACCOUNT")
        print("=" * 80)
        
        # Sort by count (descending)
        sorted_accounts = sorted(grouped_resources.items(), key=lambda x: len(x[1]), reverse=True)
        
        for account, account_resources in sorted_accounts:
            print(f"\n{account}")
            print(f"  Count: {len(account_resources)}")
            
            # Show resource type breakdown
            resource_types = {}
            for res in account_resources:
                res_type = res.get("type", "Unknown")
                resource_types[res_type] = resource_types.get(res_type, 0) + 1
            
            print(f"  Resource types:")
            for res_type, count in sorted(resource_types.items(), key=lambda x: x[1], reverse=True):
                print(f"    - {res_type}: {count}")
        
        print("\n" + "=" * 80)
        print("SUMMARY")
        print("=" * 80)
        print(f"Total Cloud Accounts: {len(grouped_resources)}")
        print(f"Total Cloud Resources: {len(resources)}")
        
        print("\nFetching discovered images count...")
        discovered_images_count = get_discovered_images_count(token)["data"]["graphSearch"]["totalCount"]
        print(f"Discovered Images (unlinked): {discovered_images_count}")
        print(f"\nGRAND TOTAL ASSETS: {len(resources) + discovered_images_count}")
        
        # Export to JSON and CSV
        print("\n" + "=" * 80)
        print("EXPORTING DATA")
        print("=" * 80)
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        script_dir = Path(__file__).parent
        
        json_path = script_dir / f"wiz_assets_{timestamp}.json"
        csv_path = script_dir / f"wiz_assets_{timestamp}.csv"
        
        export_to_json(grouped_resources, len(resources), discovered_images_count, json_path)
        export_to_csv(grouped_resources, csv_path)
        
        print("\n" + "=" * 80)
        print("✅ Export complete!")
        print("=" * 80)
        
    except Exception as e:
        print("Error:", e)