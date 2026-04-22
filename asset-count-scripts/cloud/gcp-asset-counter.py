#!/usr/bin/env python3
"""
GCP Asset Counter

This script fetches and counts all GCP resources across multiple projects.
It provides detailed asset inventory with counts by resource type.

Usage:
    python gcp-asset-counter.py
    python gcp-asset-counter.py --config custom_gcp_config.ini
    python gcp-asset-counter.py --project-id YOUR_PROJECT_ID
    python gcp-asset-counter.py --output-prefix my_assets

Dependencies:
    - google-cloud-asset
    - google-cloud-resource-manager
    - google-auth
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
    from google.cloud import asset_v1
    from google.cloud import resourcemanager_v3
    from google.oauth2 import service_account
    import google.auth
    from google.auth.exceptions import DefaultCredentialsError
    from google.api_core.exceptions import GoogleAPIError, PermissionDenied
except ImportError as e:
    print(f"Error: Required Google Cloud library is not installed: {e}")
    print("\nPlease install required libraries:")
    print("  pip install -r requirements.txt")
    sys.exit(1)


class GCPAssetCounter:
    """GCP Asset Counter - Fetches and counts GCP resources"""
    
    # GCP resource type mapping to standardized names
    RESOURCE_TYPE_MAPPING = {
        'compute.googleapis.com/Instance': 'VIRTUAL_MACHINE',
        'compute.googleapis.com/Disk': 'VOLUME',
        'compute.googleapis.com/Snapshot': 'SNAPSHOT',
        'compute.googleapis.com/Image': 'VIRTUAL_MACHINE_IMAGE',
        'compute.googleapis.com/Firewall': 'FIREWALL',
        'compute.googleapis.com/Network': 'VIRTUAL_NETWORK',
        'compute.googleapis.com/Subnetwork': 'SUBNET',
        'compute.googleapis.com/Address': 'IP_ADDRESS',
        'compute.googleapis.com/ForwardingRule': 'LOAD_BALANCER',
        'compute.googleapis.com/TargetPool': 'TARGET_GROUP',
        'compute.googleapis.com/TargetHttpProxy': 'LOAD_BALANCER',
        'compute.googleapis.com/TargetHttpsProxy': 'LOAD_BALANCER',
        'compute.googleapis.com/BackendService': 'LOAD_BALANCER',
        'compute.googleapis.com/UrlMap': 'LOAD_BALANCER',
        'compute.googleapis.com/Router': 'ROUTE_TABLE',
        'compute.googleapis.com/VpnGateway': 'GATEWAY',
        'compute.googleapis.com/VpnTunnel': 'GATEWAY',
        'storage.googleapis.com/Bucket': 'BUCKET',
        'sqladmin.googleapis.com/Instance': 'DB_SERVER',
        'sqladmin.googleapis.com/Database': 'DATABASE',
        'cloudfunctions.googleapis.com/CloudFunction': 'SERVERLESS',
        'run.googleapis.com/Service': 'SERVERLESS',
        'container.googleapis.com/Cluster': 'KUBERNETES_CLUSTER',
        'container.googleapis.com/NodePool': 'KUBERNETES_NODE',
        'artifactregistry.googleapis.com/Repository': 'CONTAINER_REPOSITORY',
        'iam.googleapis.com/Role': 'ACCESS_ROLE',
        'iam.googleapis.com/ServiceAccount': 'ACCESS_ROLE',
        'secretmanager.googleapis.com/Secret': 'SECRET',
        'cloudkms.googleapis.com/KeyRing': 'ENCRYPTION_KEY',
        'cloudkms.googleapis.com/CryptoKey': 'ENCRYPTION_KEY',
        'monitoring.googleapis.com/AlertPolicy': 'MONITOR_ALERT',
        'dns.googleapis.com/ManagedZone': 'DNS_ZONE',
        'dns.googleapis.com/Policy': 'DNS_ZONE',
        'pubsub.googleapis.com/Topic': 'MESSAGING_SERVICE',
        'pubsub.googleapis.com/Subscription': 'MESSAGING_SERVICE',
        'redis.googleapis.com/Instance': 'DATABASE',
        'bigquery.googleapis.com/Dataset': 'DATABASE',
        'bigquery.googleapis.com/Table': 'DATABASE',
        'bigtable.googleapis.com/Instance': 'DATABASE',
        'bigtable.googleapis.com/Table': 'DATABASE',
        'spanner.googleapis.com/Instance': 'DATABASE',
        'spanner.googleapis.com/Database': 'DATABASE',
        'cdn.googleapis.com/BackendBucket': 'CDN',
        'apigateway.googleapis.com/Gateway': 'API_GATEWAY',
        'apigateway.googleapis.com/Api': 'API_GATEWAY',
        'logging.googleapis.com/LogSink': 'CLOUD_LOG_CONFIGURATION',
        'cloudresourcemanager.googleapis.com/Project': 'RESOURCE_GROUP',
        'appengine.googleapis.com/Application': 'SERVERLESS',
        'appengine.googleapis.com/Service': 'SERVERLESS',
    }
    
    def __init__(self, config_file='gcp_config.ini', cloud_config_file='cloud_config.ini'):
        """Initialize GCP Asset Counter"""
        self.config_file = Path(__file__).parent / config_file
        self.cloud_config_file = Path(__file__).parent / cloud_config_file
        self.config = self.load_config()
        self.cloud_config = self.load_cloud_config()
        self.credentials = None
        self.results = {
            'scan_timestamp': datetime.utcnow().isoformat() + 'Z',
            'provider': 'GCP',
            'projects': []
        }
        
    def load_config(self) -> configparser.ConfigParser:
        """Load GCP configuration"""
        config = configparser.ConfigParser()
        if self.config_file.exists():
            print(f"Loading GCP config from {self.config_file}")
            config.read(self.config_file)
        else:
            print(f"Warning: Config file {self.config_file} not found. Using defaults.")
            config['default'] = {'auth_method': 'adc'}
            config['projects'] = {'scan_mode': 'all'}
            config['advanced'] = {'use_asset_inventory': 'true'}
        return config
    
    def load_cloud_config(self) -> configparser.ConfigParser:
        """Load cloud configuration"""
        config = configparser.ConfigParser()
        if self.cloud_config_file.exists():
            config.read(self.cloud_config_file)
        else:
            config['output'] = {
                'output_prefix': 'gcp_assets',
                'output_dir': './output',
                'include_timestamp': 'true'
            }
            config['display'] = {
                'show_progress': 'true',
                'verbose': 'false',
                'sort_by_count': 'true'
            }
        return config
    
    def get_credentials(self):
        """Get GCP credentials"""
        if self.credentials:
            return self.credentials
        
        auth_method = self.config.get('default', 'auth_method', fallback='adc')
        
        try:
            if auth_method == 'service_account':
                service_account_file = self.config.get('default', 'service_account_file')
                self.credentials, project = service_account.Credentials.from_service_account_file(
                    service_account_file,
                    scopes=['https://www.googleapis.com/auth/cloud-platform']
                )
            else:  # adc or user
                self.credentials, project = google.auth.default(
                    scopes=['https://www.googleapis.com/auth/cloud-platform']
                )
            
            return self.credentials
        except Exception as e:
            print(f"Error getting credentials: {e}")
            return None
    
    def get_projects(self):
        """Get list of GCP projects to scan"""
        credentials = self.get_credentials()
        if not credentials:
            return []
        
        try:
            scan_mode = self.config.get('projects', 'scan_mode', fallback='all')
            
            if scan_mode.lower() == 'all':
                # Get all accessible projects
                client = resourcemanager_v3.ProjectsClient(credentials=credentials)
                projects = []
                
                request = resourcemanager_v3.ListProjectsRequest()
                page_result = client.list_projects(request=request)
                
                for project in page_result:
                    if project.state == resourcemanager_v3.Project.State.ACTIVE:
                        projects.append({
                            'name': project.display_name,
                            'id': project.project_id
                        })
                
                return projects
            else:
                # Get specific projects from config
                projects = []
                for project_name, project_id in self.config.items('projects'):
                    if project_name != 'scan_mode':
                        projects.append({
                            'name': project_name,
                            'id': project_id
                        })
                return projects
                
        except Exception as e:
            print(f"Error getting projects: {e}")
            return []
    
    def count_resources_asset_inventory(self, project_id):
        """Count resources using Cloud Asset Inventory API (most efficient)"""
        credentials = self.get_credentials()
        counts = defaultdict(int)
        
        try:
            client = asset_v1.AssetServiceClient(credentials=credentials)
            
            # Prepare the request
            scope = f"projects/{project_id}"
            
            # Search all resources
            request = asset_v1.SearchAllResourcesRequest(
                scope=scope,
                page_size=500,
            )
            
            # Iterate through all pages
            page_result = client.search_all_resources(request=request)
            
            for resource in page_result:
                asset_type = resource.asset_type
                counts[asset_type] += 1
            
            return counts
            
        except PermissionDenied as e:
            print(f"  Warning: Missing Cloud Asset Inventory permissions")
            print(f"  Please grant 'cloudasset.assets.searchAllResources' permission")
            return counts
        except GoogleAPIError as e:
            print(f"  Error using Cloud Asset Inventory: {e}")
            return counts
        except Exception as e:
            print(f"  Error counting resources with Asset Inventory: {e}")
            return counts
    
    def count_project_resources(self, project_name, project_id):
        """Count all resources in a GCP project"""
        print(f"\nScanning GCP project: {project_name} ({project_id})")
        
        if self.cloud_config.getboolean('display', 'show_progress', fallback=True):
            print("  Fetching resource counts...")
        
        # Use Cloud Asset Inventory API
        use_asset_inventory = self.config.getboolean('advanced', 'use_asset_inventory', fallback=True)
        
        if use_asset_inventory:
            raw_counts = self.count_resources_asset_inventory(project_id)
        else:
            raw_counts = {}
            print("  Warning: Asset Inventory disabled, limited resource discovery")
        
        # Convert to standardized names
        standardized_counts = {}
        for asset_type, count in raw_counts.items():
            if count > 0:
                standard_name = self.RESOURCE_TYPE_MAPPING.get(
                    asset_type,
                    asset_type.replace('.', '_').replace('/', '_').upper()
                )
                if standard_name in standardized_counts:
                    standardized_counts[standard_name] += count
                else:
                    standardized_counts[standard_name] = count
        
        total_count = sum(standardized_counts.values())
        
        return {
            'account_name': project_name,
            'account_id': project_id,
            'total_count': total_count,
            'resource_types': standardized_counts
        }
    
    def scan_projects(self):
        """Scan all configured GCP projects"""
        print("=" * 80)
        print("GCP Asset Counter")
        print("=" * 80)
        
        projects = self.get_projects()
        
        if not projects:
            print("Error: No projects found or accessible")
            return
        
        print(f"\nFound {len(projects)} project(s) to scan")
        
        for project in projects:
            try:
                result = self.count_project_resources(
                    project['name'],
                    project['id']
                )
                self.results['projects'].append(result)
            except Exception as e:
                print(f"Error scanning project {project['name']}: {e}")
    
    def display_results(self):
        """Display results to console"""
        print("\n" + "=" * 80)
        print("SCAN RESULTS")
        print("=" * 80)
        
        for project in self.results['projects']:
            print(f"\nGCP:{project['account_name']} ({project['account_id']})")
            print(f"  Count: {project['total_count']}")
            
            if project['resource_types']:
                print("  Resource types:")
                
                items = project['resource_types'].items()
                if self.cloud_config.getboolean('display', 'sort_by_count', fallback=True):
                    items = sorted(items, key=lambda x: x[1], reverse=True)
                else:
                    items = sorted(items)
                
                for resource_type, count in items:
                    print(f"    - {resource_type}: {count}")
    
    def save_json(self, output_file):
        """Save results to JSON file"""
        try:
            # Rename 'projects' to 'accounts' for consistency
            output_data = {
                'scan_timestamp': self.results['scan_timestamp'],
                'provider': self.results['provider'],
                'accounts': self.results['projects']
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
                
                for project in self.results['projects']:
                    for resource_type, count in project['resource_types'].items():
                        writer.writerow([
                            self.results['provider'],
                            project['account_name'],
                            project['account_id'],
                            resource_type,
                            count,
                            self.results['scan_timestamp']
                        ])
            print(f"CSV results saved to: {output_file}")
        except Exception as e:
            print(f"Error saving CSV file: {e}")
    
    def run(self):
        """Main execution method"""
        # Scan projects
        self.scan_projects()
        
        # Display results
        self.display_results()
        
        # Prepare output directory
        output_dir = Path(self.cloud_config.get('output', 'output_dir', fallback='./output'))
        output_dir.mkdir(parents=True, exist_ok=True)
        
        # Prepare output filename
        prefix = self.cloud_config.get('output', 'output_prefix', fallback='gcp_assets')
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
        description='GCP Asset Counter - Count all GCP resources',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python gcp-asset-counter.py
  python gcp-asset-counter.py --config my_gcp_config.ini
  python gcp-asset-counter.py --project-id my-project-123456
  python gcp-asset-counter.py --output-prefix prod_assets
        """
    )
    
    parser.add_argument('--config', help='Path to GCP config file')
    parser.add_argument('--cloud-config', help='Path to cloud config file')
    parser.add_argument('--project-id', help='GCP project ID to scan')
    parser.add_argument('--output-prefix', help='Output file prefix')
    
    args = parser.parse_args()
    
    config_file = args.config if args.config else 'gcp_config.ini'
    cloud_config_file = args.cloud_config if args.cloud_config else 'cloud_config.ini'
    
    counter = GCPAssetCounter(config_file, cloud_config_file)
    
    # Override project if provided
    if args.project_id:
        counter.config['projects'] = {
            'default': args.project_id,
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







