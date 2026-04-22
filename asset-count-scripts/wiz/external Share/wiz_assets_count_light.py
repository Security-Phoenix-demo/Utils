"""
Wiz Asset Count Script (Light Version)

This script fetches cloud resources from Wiz API using aggregated groupBy queries
for better performance. It exports the data to JSON and CSV formats.

Features:
    - Groups resources by Cloud Account, Type, AND Project
    - Shows project ID and name for each resource group
    - Provides summaries by account, project, and asset type

Dependencies:
    - requests (install via: pip install -r requirements.txt)

Usage:
    # Normal mode - fetches all resources
    python wiz_assets_count_light.py output.csv
    
    # Test mode - fetches only 500 resources for testing
    python wiz_assets_count_light.py output.csv --test-mode
    
    # With credentials
    python wiz_assets_count_light.py output.csv --client-id YOUR_ID --client-secret YOUR_SECRET
    
    # Print detailed table to console as well
    python wiz_assets_count_light.py output.csv --print-table

Output Files:
    - output.csv (detailed breakdown by account, project, and asset type)
    - output_summary.csv (totals by account, project, and asset type aggregates)
    - output.json (structured data with all details including project information)
    
Console Output:
    - Summary by cloud account (total resources per account + associated projects)
    - Summary by project (total resources per project)
    - Summary by asset type (total count across all accounts)
    - Grand totals

For more information, see README.md
"""

import requests
import csv
import json
import argparse
import os
import sys
import configparser
from datetime import datetime
from pathlib import Path

AUTH_URL = "https://auth.app.wiz.io/oauth/token"
GRAPHQL_URL = "https://api.us10.app.wiz.io/graphql"

def parse_arguments():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(
        description="Wiz asset counting script (light version - uses aggregated queries)"
    )
    parser.add_argument(
        "csv_file",
        help="Path to the output CSV file to be created/populated"
    )
    parser.add_argument("--client-id", help="Wiz Client ID")
    parser.add_argument("--client-secret", help="Wiz Client Secret")
    parser.add_argument("--test-mode", action="store_true", help="Test mode: fetch only 500 resources")
    parser.add_argument("--print-table", action="store_true", help="Print table output to console")
    return parser.parse_args()

def load_credentials(args):
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

def get_assets_count(token, test_mode=False):
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
    }

    query = """
        query ResourceCountByAccTypeProjectQuery(
            $first: Int
            $after: String
        ) {
          cloudResourcesGroupedByValues(
            first: $first
            after: $after
            groupBy: {fields: [CLOUD_ACCOUNT, TYPE, PROJECT]}
          ) {
            nodes {
              cloudAccount {
                name
                externalId
                cloudProvider
              }
              project {
                id
                name
              }
              type
              analytics {
                resources {
                  count
                }
              }
            }
            pageInfo {
              hasNextPage
              endCursor
            }
          }
        }
    """
    
    if test_mode:
        print("⚠️  TEST MODE ENABLED: Fetching only first page (500 resources) for testing\n")
        
    all_rows = []
    has_next_page = True
    after_cursor = None
    test_limit = 500  # In test mode, fetch only 500 resources

    while has_next_page:
        payload = {
            "query": query,
            "variables": {
                "first": 500,
                "after": after_cursor
            }
        }

        response = requests.post(GRAPHQL_URL, json=payload, headers=headers)

        if response.status_code != 200:
            raise Exception(f"Error in get_assets_count(): {response.status_code} - {response.text}")

        data = response.json()
        resource_counts = data.get("data", {}).get("cloudResourcesGroupedByValues", {})

        for node in resource_counts.get("nodes", []):
            # Handle project info (may be null if resource is not linked to a project)
            project_info = node.get("project") or {}
            project_id = project_info.get("id", "N/A")
            project_name = project_info.get("name", "N/A")
            
            all_rows.append({
                "name": node["cloudAccount"]["name"],
                "externalId": node["cloudAccount"]["externalId"],
                "cloudProvider": node["cloudAccount"]["cloudProvider"],
                "projectId": project_id,
                "projectName": project_name,
                "resourceType": node["type"],
                "resourceCount": node["analytics"]["resources"]["count"],
            })
        
        page_info = resource_counts.get("pageInfo", {})
        has_next_page = page_info.get("hasNextPage", False)
        after_cursor = page_info.get("endCursor")
        
        print(f"Fetched {len(all_rows)} resource groups so far...")
        
        # Break early in test mode
        if test_mode and len(all_rows) >= test_limit:
            print(f"Test mode limit reached ({test_limit} resource groups)")
            has_next_page = False

    return all_rows

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
    
def calculate_summaries(asset_counts, discovered_images_count):
    """Calculate summary statistics for accounts, asset types, and projects"""
    
    # Summary by account (total resources per account)
    account_totals = {}
    
    # Summary by asset type (total across all accounts)
    asset_type_totals = {}
    
    # Summary by project (total resources per project)
    project_totals = {}
    
    for row in asset_counts:
        if row["name"] == "Discovered Images":
            # Handle discovered images separately
            asset_type_totals["CONTAINER_IMAGE"] = asset_type_totals.get("CONTAINER_IMAGE", 0) + row["resourceCount"]
            continue
        
        # Account totals
        account_key = f"{row['cloudProvider']}:{row['name']} ({row['externalId']})"
        if account_key not in account_totals:
            account_totals[account_key] = {
                "cloud_provider": row["cloudProvider"],
                "account_name": row["name"],
                "account_id": row["externalId"],
                "total_resources": 0,
                "projects": set()  # Track unique projects for this account
            }
        account_totals[account_key]["total_resources"] += row["resourceCount"]
        
        # Track project association for account
        project_id = row.get("projectId", "N/A")
        project_name = row.get("projectName", "N/A")
        if project_id and project_id != "N/A":
            account_totals[account_key]["projects"].add(f"{project_name} ({project_id})")
        
        # Asset type totals (across all accounts)
        asset_type = row["resourceType"]
        asset_type_totals[asset_type] = asset_type_totals.get(asset_type, 0) + row["resourceCount"]
        
        # Project totals
        if project_id and project_id != "N/A":
            if project_id not in project_totals:
                project_totals[project_id] = {
                    "project_id": project_id,
                    "project_name": project_name,
                    "total_resources": 0,
                    "accounts": set()  # Track unique accounts for this project
                }
            project_totals[project_id]["total_resources"] += row["resourceCount"]
            project_totals[project_id]["accounts"].add(account_key)
    
    return account_totals, asset_type_totals, project_totals

def export_summary_csv(account_totals, asset_type_totals, project_totals, discovered_images_count, output_path):
    """Export summary statistics to CSV"""
    
    with open(output_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.writer(f)
        
        # Section 1: Total by Account
        writer.writerow(["SUMMARY BY CLOUD ACCOUNT"])
        writer.writerow(["Cloud Provider", "Account Name", "Account ID", "Total Resources", "Projects"])
        writer.writerow([])  # Empty row
        
        # Sort by total resources descending
        sorted_accounts = sorted(account_totals.values(), key=lambda x: x["total_resources"], reverse=True)
        
        for account in sorted_accounts:
            # Convert projects set to sorted list for display
            projects_list = sorted(account.get("projects", set()))
            projects_str = "; ".join(projects_list) if projects_list else "N/A"
            
            writer.writerow([
                account["cloud_provider"],
                account["account_name"],
                account["account_id"],
                account["total_resources"],
                projects_str
            ])
        
        # Account summary total
        total_cloud_resources = sum(acc["total_resources"] for acc in account_totals.values())
        writer.writerow([])
        writer.writerow(["TOTAL CLOUD RESOURCES", "", "", total_cloud_resources, ""])
        
        # Section 2: Total by Project
        writer.writerow([])
        writer.writerow([])
        writer.writerow(["SUMMARY BY PROJECT"])
        writer.writerow(["Project ID", "Project Name", "Total Resources", "Number of Accounts"])
        writer.writerow([])
        
        # Sort by total resources descending
        sorted_projects = sorted(project_totals.values(), key=lambda x: x["total_resources"], reverse=True)
        
        for project in sorted_projects:
            writer.writerow([
                project["project_id"],
                project["project_name"],
                project["total_resources"],
                len(project.get("accounts", set()))
            ])
        
        # Section 3: Total by Asset Type (across all accounts)
        writer.writerow([])
        writer.writerow([])
        writer.writerow(["SUMMARY BY ASSET TYPE (ACROSS ALL ACCOUNTS)"])
        writer.writerow(["Asset Type", "Total Count"])
        writer.writerow([])
        
        # Sort by count descending
        sorted_asset_types = sorted(asset_type_totals.items(), key=lambda x: x[1], reverse=True)
        
        for asset_type, count in sorted_asset_types:
            writer.writerow([asset_type, count])
        
        # Asset type summary total
        writer.writerow([])
        writer.writerow(["GRAND TOTAL ASSETS", total_cloud_resources + discovered_images_count])
        writer.writerow(["- Cloud Resources", total_cloud_resources])
        writer.writerow(["- Discovered Images", discovered_images_count])
    
    print(f"✅ Summary CSV saved to: {output_path}")
    return output_path

def print_summary_to_console(account_totals, asset_type_totals, project_totals, discovered_images_count):
    """Print summary statistics to console"""
    
    print("\n" + "=" * 80)
    print("SUMMARY BY CLOUD ACCOUNT")
    print("=" * 80)
    
    # Sort by total resources descending
    sorted_accounts = sorted(account_totals.values(), key=lambda x: x["total_resources"], reverse=True)
    
    for account in sorted_accounts:
        print(f"{account['cloud_provider']}:{account['account_name']} ({account['account_id']})")
        print(f"  Total Resources: {account['total_resources']:,}")
        
        # Show associated projects
        projects_list = sorted(account.get("projects", set()))
        if projects_list:
            print(f"  Projects: {', '.join(projects_list)}")
    
    total_cloud_resources = sum(acc["total_resources"] for acc in account_totals.values())
    
    print("\n" + "=" * 80)
    print("SUMMARY BY PROJECT")
    print("=" * 80)
    
    # Sort by total resources descending
    sorted_projects = sorted(project_totals.values(), key=lambda x: x["total_resources"], reverse=True)
    
    for project in sorted_projects:
        print(f"{project['project_name']} (ID: {project['project_id']})")
        print(f"  Total Resources: {project['total_resources']:,}")
        print(f"  Number of Accounts: {len(project.get('accounts', set()))}")
    
    if not sorted_projects:
        print("  No projects found")
    
    print("\n" + "=" * 80)
    print("SUMMARY BY ASSET TYPE (ACROSS ALL ACCOUNTS)")
    print("=" * 80)
    
    # Sort by count descending
    sorted_asset_types = sorted(asset_type_totals.items(), key=lambda x: x[1], reverse=True)
    
    for asset_type, count in sorted_asset_types:
        print(f"  {asset_type}: {count:,}")
    
    print("\n" + "=" * 80)
    print("GRAND TOTALS")
    print("=" * 80)
    print(f"Total Cloud Accounts: {len(account_totals)}")
    print(f"Total Projects: {len(project_totals)}")
    print(f"Total Cloud Resources: {total_cloud_resources:,}")
    print(f"Discovered Images (unlinked): {discovered_images_count:,}")
    print(f"GRAND TOTAL ASSETS: {(total_cloud_resources + discovered_images_count):,}")
    print("=" * 80)

def export_to_json(asset_counts, discovered_images_count, project_totals, output_path):
    """Export asset data to JSON format"""
    
    # Group by cloud provider and account
    accounts_data = {}
    
    for row in asset_counts:
        if row["name"] == "Discovered Images":
            continue  # Handle separately
        
        account_key = f"{row['cloudProvider']}:{row['name']} ({row['externalId']})"
        
        if account_key not in accounts_data:
            accounts_data[account_key] = {
                "cloud_provider": row["cloudProvider"],
                "account_name": row["name"],
                "account_id": row["externalId"],
                "total_resources": 0,
                "projects": set(),
                "resource_types": []
            }
        
        accounts_data[account_key]["total_resources"] += row["resourceCount"]
        
        # Track project association
        project_id = row.get("projectId", "N/A")
        project_name = row.get("projectName", "N/A")
        if project_id and project_id != "N/A":
            accounts_data[account_key]["projects"].add(f"{project_name} ({project_id})")
        
        accounts_data[account_key]["resource_types"].append({
            "type": row["resourceType"],
            "count": row["resourceCount"],
            "project_id": project_id,
            "project_name": project_name
        })
    
    # Convert to list and sort by total resources
    accounts_list = []
    for acc in accounts_data.values():
        acc_copy = acc.copy()
        acc_copy["projects"] = sorted(list(acc["projects"]))  # Convert set to sorted list
        accounts_list.append(acc_copy)
    accounts_list.sort(key=lambda x: x["total_resources"], reverse=True)
    
    # Build projects list for JSON
    projects_list = []
    for project in sorted(project_totals.values(), key=lambda x: x["total_resources"], reverse=True):
        projects_list.append({
            "project_id": project["project_id"],
            "project_name": project["project_name"],
            "total_resources": project["total_resources"],
            "accounts_count": len(project.get("accounts", set()))
        })
    
    # Calculate totals
    total_cloud_resources = sum(row["resourceCount"] for row in asset_counts if row["name"] != "Discovered Images")
    
    output = {
        "export_timestamp": datetime.now().isoformat(),
        "summary": {
            "total_cloud_accounts": len(accounts_data),
            "total_projects": len(project_totals),
            "total_cloud_resources": total_cloud_resources,
            "discovered_images_unlinked": discovered_images_count,
            "grand_total_assets": total_cloud_resources + discovered_images_count
        },
        "accounts": accounts_list,
        "projects": projects_list
    }
    
    with open(output_path, 'w') as f:
        json.dump(output, f, indent=2)
    
    print(f"✅ JSON export saved to: {output_path}")
    return output_path

def print_table(columns, rows):
    """Print formatted table to console"""
    fields = list(columns.keys())
    headers = list(columns.values())

    # Build table rows (display values only)
    table_rows = [
        [str(row.get(field, "")) for field in fields]
        for row in rows
    ]

    # Compute column widths
    widths = [
        max(len(header), *(len(r[i]) for r in table_rows))
        for i, header in enumerate(headers)
    ]

    def print_row(values):
        print(" | ".join(value.ljust(widths[i]) for i, value in enumerate(values)))

    def print_separator():
        print("-+-".join("-" * w for w in widths))

    print("\n" + "=" * 80)
    print("ASSET COUNT BY ACCOUNT AND TYPE")
    print("=" * 80 + "\n")
    
    # Header
    print_row(headers)
    print_separator()

    # Data rows
    for values in table_rows:
        print_row(values)
    
    print("\n" + "=" * 80)

if __name__ == "__main__":
    try:
        # Parse arguments and load credentials
        args = parse_arguments()
        client_id, client_secret = load_credentials(args)
        
        print("\nAuthenticating with Wiz API...")
        token = get_token(client_id, client_secret)
        print("Authentication successful!\n")
        
        print("Fetching cloud resources (grouped by account and type)...")
        asset_counts = get_assets_count(token, test_mode=args.test_mode)
        
        print("\nFetching discovered images count...")
        discovered_images_count = get_discovered_images_count(token)["data"]["graphSearch"]["totalCount"]
        
        # Add discovered images to the dataset
        asset_counts.append({
            "name": "Discovered Images",
            "externalId": "not-real-account",
            "cloudProvider": "Various",
            "projectId": "N/A",
            "projectName": "N/A",
            "resourceType": "CONTAINER_IMAGE",
            "resourceCount": discovered_images_count,
        })
        
        # Calculate summaries
        account_totals, asset_type_totals, project_totals = calculate_summaries(asset_counts, discovered_images_count)
        
        # Print summary to console
        print_summary_to_console(account_totals, asset_type_totals, project_totals, discovered_images_count)
        
        if args.test_mode:
            print("\n⚠️  Note: Test mode was enabled - data may be incomplete")
        
        # Export files
        print("\n" + "=" * 80)
        print("EXPORTING DATA")
        print("=" * 80)
        
        # Define fieldnames for detailed CSV
        fieldnames = {
            "name": "Account Name",
            "externalId": "Account ID",
            "cloudProvider": "Provider",
            "projectId": "Project ID",
            "projectName": "Project Name",
            "resourceType": "Asset Type",
            "resourceCount": "Asset Count",
        }
        
        # Export to detailed CSV (with resource types)
        print(f"\nExporting detailed data to CSV: {args.csv_file}")
        with open(args.csv_file, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames.values())
            writer.writeheader()
            for row in asset_counts:
                writer.writerow({
                    fieldnames[key]: row[key]
                    for key in fieldnames.keys()
                })
        print(f"✅ Detailed CSV saved to: {args.csv_file}")
        
        # Export to summary CSV
        csv_path = Path(args.csv_file)
        summary_csv_filename = csv_path.stem + "_summary.csv"
        summary_csv_path = csv_path.parent / summary_csv_filename
        export_summary_csv(account_totals, asset_type_totals, project_totals, discovered_images_count, summary_csv_path)
        
        # Export to JSON (auto-generate filename based on CSV name)
        json_filename = csv_path.stem + ".json"
        json_path = csv_path.parent / json_filename
        export_to_json(asset_counts, discovered_images_count, project_totals, json_path)
        
        # Print detailed table if requested
        if args.print_table:
            print_table(fieldnames, asset_counts)
        
        print("\n" + "=" * 80)
        print("✅ Export complete!")
        print("=" * 80)
        print(f"\nFiles created:")
        print(f"  1. Detailed CSV: {args.csv_file}")
        print(f"  2. Summary CSV:  {summary_csv_path}")
        print(f"  3. JSON:         {json_path}")
        print("=" * 80)

    except Exception as e:
        print(f"\n❌ Error: {e}")
        sys.exit(1)
