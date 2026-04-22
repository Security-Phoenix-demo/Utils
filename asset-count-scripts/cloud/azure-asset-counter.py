#!/usr/bin/env python3
"""
Azure Asset Counter

This script fetches and counts all Azure resources across multiple subscriptions.
It provides detailed asset inventory with counts by resource type.

Usage:
    python azure-asset-counter.py
    python azure-asset-counter.py --config custom_azure_config.ini
    python azure-asset-counter.py --subscription-id YOUR_SUB_ID
    python azure-asset-counter.py --output-prefix my_assets

Dependencies:
    - azure-identity
    - azure-mgmt-resource
    - azure-mgmt-resourcegraph
    See requirements.txt for full list

For more information, see README.md
"""

import os
import sys
import json
import csv
import argparse
import configparser
from pathlib import Path
from datetime import datetime
from collections import defaultdict
from typing import Dict, List, Any
import time

# Check for required libraries
try:
    from azure.identity import DefaultAzureCredential, ClientSecretCredential, ManagedIdentityCredential
    from azure.mgmt.resource import ResourceManagementClient, SubscriptionClient
    from azure.mgmt.resourcegraph import ResourceGraphClient
    from azure.mgmt.resourcegraph.models import QueryRequest
    from azure.core.exceptions import AzureError, HttpResponseError
except ImportError as e:
    print(f"Error: Required Azure library is not installed: {e}")
    print("\nPlease install required libraries:")
    print("  pip install -r requirements.txt")
    sys.exit(1)


class AzureAssetCounter:
    """Azure Asset Counter - Fetches and counts Azure resources"""
    
    # Azure resource type mapping to standardized names
    RESOURCE_TYPE_MAPPING = {
        'microsoft.compute/virtualmachines': 'VIRTUAL_MACHINE',
        'microsoft.compute/disks': 'VOLUME',
        'microsoft.compute/snapshots': 'SNAPSHOT',
        'microsoft.compute/images': 'VIRTUAL_MACHINE_IMAGE',
        'microsoft.network/networksecuritygroups': 'FIREWALL',
        'microsoft.network/virtualnetworks': 'VIRTUAL_NETWORK',
        'microsoft.network/subnets': 'SUBNET',
        'microsoft.network/networkinterfaces': 'NETWORK_INTERFACE',
        'microsoft.network/routetables': 'ROUTE_TABLE',
        'microsoft.network/virtualnetworkgateways': 'GATEWAY',
        'microsoft.network/natgateways': 'GATEWAY',
        'microsoft.network/applicationgateways': 'GATEWAY',
        'microsoft.network/publicipaddresses': 'IP_ADDRESS',
        'microsoft.network/loadbalancers': 'LOAD_BALANCER',
        'microsoft.network/trafficmanagerprofiles': 'LOAD_BALANCER',
        'microsoft.network/frontdoors': 'LOAD_BALANCER',
        'microsoft.network/privateendpoints': 'PRIVATE_ENDPOINT',
        'microsoft.network/dnszones': 'DNS_ZONE',
        'microsoft.network/privatednszones': 'DNS_ZONE',
        'microsoft.storage/storageaccounts': 'BUCKET',
        'microsoft.sql/servers': 'DB_SERVER',
        'microsoft.sql/servers/databases': 'DATABASE',
        'microsoft.dbforpostgresql/servers': 'DB_SERVER',
        'microsoft.dbformysql/servers': 'DB_SERVER',
        'microsoft.documentdb/databaseaccounts': 'DATABASE',
        'microsoft.web/sites': 'SERVERLESS',
        'microsoft.web/serverfarms': 'SERVICE_CONFIGURATION',
        'microsoft.containerservice/managedclusters': 'KUBERNETES_CLUSTER',
        'microsoft.containerinstance/containergroups': 'CONTAINER_GROUP',
        'microsoft.containerregistry/registries': 'CONTAINER_REGISTRY',
        'microsoft.keyvault/vaults': 'SECRET_CONTAINER',
        'microsoft.keyvault/vaults/secrets': 'SECRET',
        'microsoft.keyvault/vaults/keys': 'ENCRYPTION_KEY',
        'microsoft.insights/metricalerts': 'MONITOR_ALERT',
        'microsoft.insights/activitylogalerts': 'MONITOR_ALERT',
        'microsoft.insights/components': 'MONITOR_ALERT',
        'microsoft.authorization/roleassignments': 'ACCESS_ROLE_BINDING',
        'microsoft.authorization/roledefinitions': 'ACCESS_ROLE',
        'microsoft.authorization/policyassignments': 'RAW_ACCESS_POLICY',
        'microsoft.authorization/policydefinitions': 'RAW_ACCESS_POLICY',
        'microsoft.cdn/profiles': 'CDN',
        'microsoft.apimanagement/service': 'API_GATEWAY',
        'microsoft.servicebus/namespaces': 'MESSAGING_SERVICE',
        'microsoft.eventhub/namespaces': 'MESSAGING_SERVICE',
        'microsoft.cache/redis': 'DATABASE',
        'microsoft.operationalinsights/workspaces': 'CLOUD_LOG_CONFIGURATION',
        'microsoft.recoveryservices/vaults': 'BACKUP_SERVICE',
        'microsoft.resources/resourcegroups': 'RESOURCE_GROUP',
        'microsoft.managedidentity/userassignedidentities': 'ACCESS_ROLE',
    }
    
    def __init__(self, config_file='azure_config.ini', cloud_config_file='cloud_config.ini'):
        """Initialize Azure Asset Counter"""
        self.config_file = Path(__file__).parent / config_file
        self.cloud_config_file = Path(__file__).parent / cloud_config_file
        self.config = self.load_config()
        self.cloud_config = self.load_cloud_config()
        self.credential = None
        self.results = {
            'scan_timestamp': datetime.utcnow().isoformat() + 'Z',
            'provider': 'Azure',
            'subscriptions': []
        }
        
    def load_config(self) -> configparser.ConfigParser:
        """Load Azure configuration"""
        config = configparser.ConfigParser()
        if self.config_file.exists():
            print(f"Loading Azure config from {self.config_file}")
            config.read(self.config_file)
        else:
            print(f"Warning: Config file {self.config_file} not found. Using defaults.")
            config['default'] = {'auth_method': 'cli'}
            config['subscriptions'] = {'scan_mode': 'all'}
        return config
    
    def load_cloud_config(self) -> configparser.ConfigParser:
        """Load cloud configuration"""
        config = configparser.ConfigParser()
        if self.cloud_config_file.exists():
            config.read(self.cloud_config_file)
        else:
            config['output'] = {
                'output_prefix': 'azure_assets',
                'output_dir': './output',
                'include_timestamp': 'true'
            }
            config['display'] = {
                'show_progress': 'true',
                'verbose': 'false',
                'sort_by_count': 'true'
            }
        return config
    
    def get_credential(self):
        """Create Azure credential"""
        if self.credential:
            return self.credential
        
        auth_method = self.config.get('default', 'auth_method', fallback='cli')
        
        try:
            if auth_method == 'service_principal':
                tenant_id = self.config.get('default', 'tenant_id')
                client_id = self.config.get('default', 'client_id')
                client_secret = self.config.get('default', 'client_secret')
                self.credential = ClientSecretCredential(tenant_id, client_id, client_secret)
            elif auth_method == 'managed_identity':
                client_id = self.config.get('default', 'client_id', fallback=None)
                if client_id:
                    self.credential = ManagedIdentityCredential(client_id=client_id)
                else:
                    self.credential = ManagedIdentityCredential()
            else:  # cli or default
                self.credential = DefaultAzureCredential()
            
            return self.credential
        except Exception as e:
            print(f"Error creating credential: {e}")
            return None
    
    def get_subscriptions(self):
        """Get list of Azure subscriptions to scan"""
        credential = self.get_credential()
        if not credential:
            return []
        
        try:
            subscription_client = SubscriptionClient(credential)
            
            # Check if specific subscriptions are configured
            scan_mode = self.config.get('subscriptions', 'scan_mode', fallback='all')
            
            if scan_mode.lower() == 'all':
                # Get all accessible subscriptions
                subscriptions = []
                for sub in subscription_client.subscriptions.list():
                    subscriptions.append({
                        'name': sub.display_name,
                        'id': sub.subscription_id
                    })
                return subscriptions
            else:
                # Get specific subscriptions from config
                subscriptions = []
                for sub_name, sub_id in self.config.items('subscriptions'):
                    if sub_name != 'scan_mode':
                        subscriptions.append({
                            'name': sub_name,
                            'id': sub_id
                        })
                return subscriptions
                
        except Exception as e:
            print(f"Error getting subscriptions: {e}")
            return []
    
    def count_resources_resource_graph(self, subscription_id):
        """Count resources using Azure Resource Graph (most efficient method)"""
        credential = self.get_credential()
        counts = defaultdict(int)
        
        try:
            # Create Resource Graph client
            resource_graph_client = ResourceGraphClient(credential)
            
            # Query to get all resources with their types
            query = """
            Resources
            | where subscriptionId == '{}'
            | summarize count() by type
            | order by count_ desc
            """.format(subscription_id)
            
            query_request = QueryRequest(
                subscriptions=[subscription_id],
                query=query
            )
            
            response = resource_graph_client.resources(query_request)
            
            # Process results
            for row in response.data:
                resource_type = row['type'].lower()
                count = row['count_']
                counts[resource_type] = count
            
            return counts
            
        except HttpResponseError as e:
            if 'AuthorizationFailed' in str(e) or 'Forbidden' in str(e):
                print(f"  Warning: Missing Resource Graph permissions, falling back to Resource Manager API")
                return self.count_resources_resource_manager(subscription_id)
            else:
                print(f"  Error using Resource Graph: {e}")
                return counts
        except Exception as e:
            print(f"  Error counting resources with Resource Graph: {e}")
            return self.count_resources_resource_manager(subscription_id)
    
    def count_resources_resource_manager(self, subscription_id):
        """Count resources using Resource Manager API (fallback method)"""
        credential = self.get_credential()
        counts = defaultdict(int)
        
        try:
            resource_client = ResourceManagementClient(credential, subscription_id)
            
            # List all resources
            for resource in resource_client.resources.list():
                resource_type = resource.type.lower()
                counts[resource_type] += 1
            
            return counts
            
        except Exception as e:
            print(f"  Error counting resources with Resource Manager: {e}")
            return counts
    
    def count_subscription_resources(self, subscription_name, subscription_id):
        """Count all resources in an Azure subscription"""
        print(f"\nScanning Azure subscription: {subscription_name} ({subscription_id})")
        
        if self.cloud_config.getboolean('display', 'show_progress', fallback=True):
            print("  Fetching resource counts...")
        
        # Use Resource Graph API (preferred) or fall back to Resource Manager
        raw_counts = self.count_resources_resource_graph(subscription_id)
        
        # Convert to standardized names
        standardized_counts = {}
        for resource_type, count in raw_counts.items():
            if count > 0:
                standard_name = self.RESOURCE_TYPE_MAPPING.get(
                    resource_type,
                    resource_type.upper().replace('.', '_').replace('/', '_')
                )
                if standard_name in standardized_counts:
                    standardized_counts[standard_name] += count
                else:
                    standardized_counts[standard_name] = count
        
        total_count = sum(standardized_counts.values())
        
        return {
            'account_name': subscription_name,
            'account_id': subscription_id,
            'total_count': total_count,
            'resource_types': standardized_counts
        }
    
    def scan_subscriptions(self):
        """Scan all configured Azure subscriptions"""
        print("=" * 80)
        print("Azure Asset Counter")
        print("=" * 80)
        
        subscriptions = self.get_subscriptions()
        
        if not subscriptions:
            print("Error: No subscriptions found or accessible")
            return
        
        print(f"\nFound {len(subscriptions)} subscription(s) to scan")
        
        for subscription in subscriptions:
            try:
                result = self.count_subscription_resources(
                    subscription['name'],
                    subscription['id']
                )
                self.results['subscriptions'].append(result)
            except Exception as e:
                print(f"Error scanning subscription {subscription['name']}: {e}")
    
    def display_results(self):
        """Display results to console"""
        print("\n" + "=" * 80)
        print("SCAN RESULTS")
        print("=" * 80)
        
        for subscription in self.results['subscriptions']:
            print(f"\nAzure:{subscription['account_name']} ({subscription['account_id']})")
            print(f"  Count: {subscription['total_count']}")
            
            if subscription['resource_types']:
                print("  Resource types:")
                
                items = subscription['resource_types'].items()
                if self.cloud_config.getboolean('display', 'sort_by_count', fallback=True):
                    items = sorted(items, key=lambda x: x[1], reverse=True)
                else:
                    items = sorted(items)
                
                for resource_type, count in items:
                    print(f"    - {resource_type}: {count}")
    
    def save_json(self, output_file):
        """Save results to JSON file"""
        try:
            # Rename 'subscriptions' to 'accounts' for consistency
            output_data = {
                'scan_timestamp': self.results['scan_timestamp'],
                'provider': self.results['provider'],
                'accounts': self.results['subscriptions']
            }
            
            with open(output_file, 'w') as f:
                json.dump(output_data, f, indent=2)
            print(f"\nJSON results saved to: {output_file}")
        except Exception as e:
            print(f"Error saving JSON file: {e}")
    
    def save_csv(self, output_file):
        """Save results to CSV file"""
        try:
            with open(output_file, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['Provider', 'AccountName', 'AccountID', 'ResourceType', 'Count', 'ScanTimestamp'])
                
                for subscription in self.results['subscriptions']:
                    for resource_type, count in subscription['resource_types'].items():
                        writer.writerow([
                            self.results['provider'],
                            subscription['account_name'],
                            subscription['account_id'],
                            resource_type,
                            count,
                            self.results['scan_timestamp']
                        ])
            print(f"CSV results saved to: {output_file}")
        except Exception as e:
            print(f"Error saving CSV file: {e}")
    
    def run(self):
        """Main execution method"""
        # Scan subscriptions
        self.scan_subscriptions()
        
        # Display results
        self.display_results()
        
        # Prepare output directory
        output_dir = Path(self.cloud_config.get('output', 'output_dir', fallback='./output'))
        output_dir.mkdir(parents=True, exist_ok=True)
        
        # Prepare output filename
        prefix = self.cloud_config.get('output', 'output_prefix', fallback='azure_assets')
        include_timestamp = self.cloud_config.getboolean('output', 'include_timestamp', fallback=True)
        
        if include_timestamp:
            timestamp = datetime.now().strftime('%Y%m%d_%H%M')
            base_name = f"{prefix}_{timestamp}"
        else:
            base_name = prefix
        
        # Save results
        json_file = output_dir / f"{base_name}.json"
        csv_file = output_dir / f"{base_name}.csv"
        
        self.save_json(json_file)
        self.save_csv(csv_file)
        
        print("\n" + "=" * 80)
        print("Scan complete!")
        print("=" * 80)


def main():
    """Main entry point"""
    parser = argparse.ArgumentParser(
        description='Azure Asset Counter - Count all Azure resources',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python azure-asset-counter.py
  python azure-asset-counter.py --config my_azure_config.ini
  python azure-asset-counter.py --subscription-id 12345678-1234-1234-1234-123456789012
  python azure-asset-counter.py --output-prefix prod_assets
        """
    )
    
    parser.add_argument('--config', help='Path to Azure config file')
    parser.add_argument('--cloud-config', help='Path to cloud config file')
    parser.add_argument('--subscription-id', help='Azure subscription ID to scan')
    parser.add_argument('--output-prefix', help='Output file prefix')
    
    args = parser.parse_args()
    
    config_file = args.config if args.config else 'azure_config.ini'
    cloud_config_file = args.cloud_config if args.cloud_config else 'cloud_config.ini'
    
    counter = AzureAssetCounter(config_file, cloud_config_file)
    
    # Override subscription if provided
    if args.subscription_id:
        counter.config['subscriptions'] = {
            'default': args.subscription_id,
            'scan_mode': 'specific'
        }
    
    # Override output prefix if provided
    if args.output_prefix:
        counter.cloud_config['output']['output_prefix'] = args.output_prefix
    
    try:
        counter.run()
    except KeyboardInterrupt:
        print("\n\nScan interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\nError: {e}")
        if counter.cloud_config.getboolean('display', 'verbose', fallback=False):
            import traceback
            traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()







