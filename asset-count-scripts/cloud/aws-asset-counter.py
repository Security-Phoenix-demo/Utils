#!/usr/bin/env python3
"""
AWS Asset Counter

This script fetches and counts all AWS resources across multiple accounts and regions.
It provides detailed asset inventory with counts by resource type.

Usage:
    python aws-asset-counter.py
    python aws-asset-counter.py --config custom_aws_config.ini
    python aws-asset-counter.py --profile my-aws-profile
    python aws-asset-counter.py --output-prefix my_assets

Dependencies:
    - boto3
    - botocore
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
from typing import Dict, List, Tuple, Any
import time

# Check for required libraries
try:
    import boto3
    from botocore.exceptions import ClientError, BotoCoreError, NoCredentialsError
except ImportError:
    print("Error: 'boto3' library is not installed.")
    print("\nPlease install required libraries:")
    print("  pip install -r requirements.txt")
    sys.exit(1)


class AWSAssetCounter:
    """AWS Asset Counter - Fetches and counts AWS resources"""
    
    # AWS resource type mapping to standardized names
    RESOURCE_TYPE_MAPPING = {
        'ec2:instance': 'VIRTUAL_MACHINE',
        'ec2:volume': 'VOLUME',
        'ec2:snapshot': 'SNAPSHOT',
        'ec2:image': 'VIRTUAL_MACHINE_IMAGE',
        'ec2:security-group': 'FIREWALL',
        'ec2:vpc': 'VIRTUAL_NETWORK',
        'ec2:subnet': 'SUBNET',
        'ec2:network-interface': 'NETWORK_INTERFACE',
        'ec2:route-table': 'ROUTE_TABLE',
        'ec2:internet-gateway': 'GATEWAY',
        'ec2:nat-gateway': 'GATEWAY',
        'ec2:vpn-gateway': 'GATEWAY',
        'ec2:eip': 'IP_ADDRESS',
        'ec2:target-group': 'TARGET_GROUP',
        's3:bucket': 'BUCKET',
        'rds:db': 'DB_SERVER',
        'rds:snapshot': 'SNAPSHOT',
        'rds:cluster': 'DB_SERVER',
        'lambda:function': 'SERVERLESS',
        'ecs:cluster': 'CONTAINER_SERVICE',
        'ecs:service': 'CONTAINER_SERVICE',
        'ecs:task': 'CONTAINER',
        'eks:cluster': 'KUBERNETES_CLUSTER',
        'eks:nodegroup': 'KUBERNETES_NODE',
        'ecr:repository': 'CONTAINER_REPOSITORY',
        'iam:role': 'ACCESS_ROLE',
        'iam:policy': 'RAW_ACCESS_POLICY',
        'iam:user': 'ACCESS_ROLE',
        'iam:group': 'ACCESS_ROLE',
        'secretsmanager:secret': 'SECRET',
        'kms:key': 'ENCRYPTION_KEY',
        'cloudwatch:alarm': 'MONITOR_ALERT',
        'elb:loadbalancer': 'LOAD_BALANCER',
        'elbv2:loadbalancer': 'LOAD_BALANCER',
        'route53:hostedzone': 'DNS_ZONE',
        'route53:recordset': 'DNS_RECORD',
        'dynamodb:table': 'DATABASE',
        'sns:topic': 'MESSAGING_SERVICE',
        'sqs:queue': 'MESSAGING_SERVICE',
        'elasticache:cluster': 'DATABASE',
        'redshift:cluster': 'DATABASE',
        'cloudfront:distribution': 'CDN',
        'apigateway:restapi': 'API_GATEWAY',
        'apigateway:api': 'API_GATEWAY',
    }
    
    def __init__(self, config_file='aws_config.ini', cloud_config_file='cloud_config.ini'):
        """Initialize AWS Asset Counter"""
        self.config_file = Path(__file__).parent / config_file
        self.cloud_config_file = Path(__file__).parent / cloud_config_file
        self.config = self.load_config()
        self.cloud_config = self.load_cloud_config()
        self.session = None
        self.results = {
            'scan_timestamp': datetime.utcnow().isoformat() + 'Z',
            'provider': 'AWS',
            'accounts': []
        }
        
    def load_config(self) -> configparser.ConfigParser:
        """Load AWS configuration"""
        config = configparser.ConfigParser()
        if self.config_file.exists():
            print(f"Loading AWS config from {self.config_file}")
            config.read(self.config_file)
        else:
            print(f"Warning: Config file {self.config_file} not found. Using defaults.")
            # Set defaults
            config['default'] = {
                'auth_method': 'profile',
                'default_region': 'us-east-1'
            }
            config['regions'] = {'scan_regions': 'all'}
        return config
    
    def load_cloud_config(self) -> configparser.ConfigParser:
        """Load cloud configuration"""
        config = configparser.ConfigParser()
        if self.cloud_config_file.exists():
            config.read(self.cloud_config_file)
        else:
            # Set defaults
            config['output'] = {
                'output_prefix': 'aws_assets',
                'output_dir': './output',
                'include_timestamp': 'true'
            }
            config['display'] = {
                'show_progress': 'true',
                'verbose': 'false',
                'sort_by_count': 'true'
            }
        return config
    
    def get_session(self, profile_name=None, role_arn=None):
        """Create boto3 session with credentials"""
        try:
            if role_arn:
                # Assume role
                sts_client = boto3.client('sts')
                assumed_role = sts_client.assume_role(
                    RoleArn=role_arn,
                    RoleSessionName='AssetCounterSession'
                )
                credentials = assumed_role['Credentials']
                return boto3.Session(
                    aws_access_key_id=credentials['AccessKeyId'],
                    aws_secret_access_key=credentials['SecretAccessKey'],
                    aws_session_token=credentials['SessionToken']
                )
            elif profile_name:
                return boto3.Session(profile_name=profile_name)
            else:
                return boto3.Session()
        except Exception as e:
            print(f"Error creating session: {e}")
            return None
    
    def get_all_regions(self, session):
        """Get all enabled AWS regions"""
        try:
            ec2 = session.client('ec2', region_name='us-east-1')
            regions = ec2.describe_regions()['Regions']
            return [region['RegionName'] for region in regions]
        except Exception as e:
            print(f"Error fetching regions: {e}")
            return ['us-east-1', 'us-west-2', 'eu-west-1']  # Fallback regions
    
    def get_account_id(self, session):
        """Get AWS account ID"""
        try:
            sts = session.client('sts')
            return sts.get_caller_identity()['Account']
        except Exception as e:
            print(f"Error getting account ID: {e}")
            return 'unknown'
    
    def get_account_alias(self, session):
        """Get AWS account alias"""
        try:
            iam = session.client('iam')
            aliases = iam.list_account_aliases()['AccountAliases']
            return aliases[0] if aliases else None
        except Exception as e:
            return None
    
    def count_ec2_resources(self, session, region):
        """Count EC2 resources"""
        counts = defaultdict(int)
        try:
            ec2 = session.client('ec2', region_name=region)
            
            # Instances
            instances = ec2.describe_instances()
            for reservation in instances.get('Reservations', []):
                counts['ec2:instance'] += len(reservation.get('Instances', []))
            
            # Volumes
            volumes = ec2.describe_volumes()
            counts['ec2:volume'] = len(volumes.get('Volumes', []))
            
            # Snapshots (owned by account)
            account_id = self.get_account_id(session)
            snapshots = ec2.describe_snapshots(OwnerIds=[account_id])
            counts['ec2:snapshot'] = len(snapshots.get('Snapshots', []))
            
            # AMIs
            images = ec2.describe_images(Owners=['self'])
            counts['ec2:image'] = len(images.get('Images', []))
            
            # Security Groups
            sgs = ec2.describe_security_groups()
            counts['ec2:security-group'] = len(sgs.get('SecurityGroups', []))
            
            # VPCs
            vpcs = ec2.describe_vpcs()
            counts['ec2:vpc'] = len(vpcs.get('Vpcs', []))
            
            # Subnets
            subnets = ec2.describe_subnets()
            counts['ec2:subnet'] = len(subnets.get('Subnets', []))
            
            # Network Interfaces
            enis = ec2.describe_network_interfaces()
            counts['ec2:network-interface'] = len(enis.get('NetworkInterfaces', []))
            
            # Route Tables
            route_tables = ec2.describe_route_tables()
            counts['ec2:route-table'] = len(route_tables.get('RouteTables', []))
            
            # Internet Gateways
            igws = ec2.describe_internet_gateways()
            counts['ec2:internet-gateway'] = len(igws.get('InternetGateways', []))
            
            # NAT Gateways
            nat_gws = ec2.describe_nat_gateways()
            counts['ec2:nat-gateway'] = len(nat_gws.get('NatGateways', []))
            
            # Elastic IPs
            eips = ec2.describe_addresses()
            counts['ec2:eip'] = len(eips.get('Addresses', []))
            
        except ClientError as e:
            if 'UnauthorizedOperation' not in str(e):
                print(f"  Warning: Error counting EC2 resources in {region}: {e}")
        except Exception as e:
            print(f"  Warning: Error counting EC2 resources in {region}: {e}")
        
        return counts
    
    def count_s3_resources(self, session):
        """Count S3 resources (global service)"""
        counts = defaultdict(int)
        try:
            s3 = session.client('s3')
            buckets = s3.list_buckets()
            counts['s3:bucket'] = len(buckets.get('Buckets', []))
        except Exception as e:
            print(f"  Warning: Error counting S3 resources: {e}")
        return counts
    
    def count_rds_resources(self, session, region):
        """Count RDS resources"""
        counts = defaultdict(int)
        try:
            rds = session.client('rds', region_name=region)
            
            # DB Instances
            db_instances = rds.describe_db_instances()
            counts['rds:db'] = len(db_instances.get('DBInstances', []))
            
            # DB Clusters
            db_clusters = rds.describe_db_clusters()
            counts['rds:cluster'] = len(db_clusters.get('DBClusters', []))
            
            # Snapshots
            snapshots = rds.describe_db_snapshots()
            counts['rds:snapshot'] = len(snapshots.get('DBSnapshots', []))
            
        except Exception as e:
            if 'AccessDenied' not in str(e):
                print(f"  Warning: Error counting RDS resources in {region}: {e}")
        return counts
    
    def count_lambda_resources(self, session, region):
        """Count Lambda resources"""
        counts = defaultdict(int)
        try:
            lambda_client = session.client('lambda', region_name=region)
            paginator = lambda_client.get_paginator('list_functions')
            for page in paginator.paginate():
                counts['lambda:function'] += len(page.get('Functions', []))
        except Exception as e:
            if 'AccessDenied' not in str(e):
                print(f"  Warning: Error counting Lambda resources in {region}: {e}")
        return counts
    
    def count_ecs_resources(self, session, region):
        """Count ECS resources"""
        counts = defaultdict(int)
        try:
            ecs = session.client('ecs', region_name=region)
            
            # Clusters
            cluster_arns = ecs.list_clusters().get('clusterArns', [])
            counts['ecs:cluster'] = len(cluster_arns)
            
            # Services (across all clusters)
            for cluster_arn in cluster_arns:
                services = ecs.list_services(cluster=cluster_arn).get('serviceArns', [])
                counts['ecs:service'] += len(services)
                
                # Tasks
                tasks = ecs.list_tasks(cluster=cluster_arn).get('taskArns', [])
                counts['ecs:task'] += len(tasks)
                
        except Exception as e:
            if 'AccessDenied' not in str(e):
                print(f"  Warning: Error counting ECS resources in {region}: {e}")
        return counts
    
    def count_eks_resources(self, session, region):
        """Count EKS resources"""
        counts = defaultdict(int)
        try:
            eks = session.client('eks', region_name=region)
            
            # Clusters
            clusters = eks.list_clusters().get('clusters', [])
            counts['eks:cluster'] = len(clusters)
            
            # Node groups
            for cluster in clusters:
                nodegroups = eks.list_nodegroups(clusterName=cluster).get('nodegroups', [])
                counts['eks:nodegroup'] += len(nodegroups)
                
        except Exception as e:
            if 'AccessDenied' not in str(e):
                print(f"  Warning: Error counting EKS resources in {region}: {e}")
        return counts
    
    def count_ecr_resources(self, session, region):
        """Count ECR resources"""
        counts = defaultdict(int)
        try:
            ecr = session.client('ecr', region_name=region)
            repositories = ecr.describe_repositories().get('repositories', [])
            counts['ecr:repository'] = len(repositories)
        except Exception as e:
            if 'AccessDenied' not in str(e):
                print(f"  Warning: Error counting ECR resources in {region}: {e}")
        return counts
    
    def count_iam_resources(self, session):
        """Count IAM resources (global service)"""
        counts = defaultdict(int)
        try:
            iam = session.client('iam')
            
            # Roles
            paginator = iam.get_paginator('list_roles')
            for page in paginator.paginate():
                counts['iam:role'] += len(page.get('Roles', []))
            
            # Policies
            paginator = iam.get_paginator('list_policies')
            for page in paginator.paginate(Scope='Local'):
                counts['iam:policy'] += len(page.get('Policies', []))
            
            # Users
            paginator = iam.get_paginator('list_users')
            for page in paginator.paginate():
                counts['iam:user'] += len(page.get('Users', []))
            
            # Groups
            paginator = iam.get_paginator('list_groups')
            for page in paginator.paginate():
                counts['iam:group'] += len(page.get('Groups', []))
                
        except Exception as e:
            if 'AccessDenied' not in str(e):
                print(f"  Warning: Error counting IAM resources: {e}")
        return counts
    
    def count_secrets_resources(self, session, region):
        """Count Secrets Manager resources"""
        counts = defaultdict(int)
        try:
            sm = session.client('secretsmanager', region_name=region)
            paginator = sm.get_paginator('list_secrets')
            for page in paginator.paginate():
                counts['secretsmanager:secret'] += len(page.get('SecretList', []))
        except Exception as e:
            if 'AccessDenied' not in str(e):
                print(f"  Warning: Error counting Secrets Manager resources in {region}: {e}")
        return counts
    
    def count_kms_resources(self, session, region):
        """Count KMS resources"""
        counts = defaultdict(int)
        try:
            kms = session.client('kms', region_name=region)
            paginator = kms.get_paginator('list_keys')
            for page in paginator.paginate():
                counts['kms:key'] += len(page.get('Keys', []))
        except Exception as e:
            if 'AccessDenied' not in str(e):
                print(f"  Warning: Error counting KMS resources in {region}: {e}")
        return counts
    
    def count_cloudwatch_resources(self, session, region):
        """Count CloudWatch resources"""
        counts = defaultdict(int)
        try:
            cw = session.client('cloudwatch', region_name=region)
            paginator = cw.get_paginator('describe_alarms')
            for page in paginator.paginate():
                counts['cloudwatch:alarm'] += len(page.get('MetricAlarms', []))
        except Exception as e:
            if 'AccessDenied' not in str(e):
                print(f"  Warning: Error counting CloudWatch resources in {region}: {e}")
        return counts
    
    def count_elb_resources(self, session, region):
        """Count ELB resources"""
        counts = defaultdict(int)
        try:
            # Classic Load Balancers
            elb = session.client('elb', region_name=region)
            lbs = elb.describe_load_balancers().get('LoadBalancerDescriptions', [])
            counts['elb:loadbalancer'] = len(lbs)
            
            # Application/Network Load Balancers
            elbv2 = session.client('elbv2', region_name=region)
            lbs_v2 = elbv2.describe_load_balancers().get('LoadBalancers', [])
            counts['elbv2:loadbalancer'] = len(lbs_v2)
            
            # Target Groups
            tgs = elbv2.describe_target_groups().get('TargetGroups', [])
            counts['ec2:target-group'] = len(tgs)
            
        except Exception as e:
            if 'AccessDenied' not in str(e):
                print(f"  Warning: Error counting ELB resources in {region}: {e}")
        return counts
    
    def count_other_resources(self, session, region):
        """Count other AWS resources"""
        counts = defaultdict(int)
        
        # Route53 (global)
        try:
            r53 = session.client('route53')
            zones = r53.list_hosted_zones().get('HostedZones', [])
            counts['route53:hostedzone'] = len(zones)
            for zone in zones:
                records = r53.list_resource_record_sets(HostedZoneId=zone['Id'])
                counts['route53:recordset'] += len(records.get('ResourceRecordSets', []))
        except Exception as e:
            pass
        
        # DynamoDB
        try:
            dynamodb = session.client('dynamodb', region_name=region)
            tables = dynamodb.list_tables().get('TableNames', [])
            counts['dynamodb:table'] = len(tables)
        except Exception as e:
            pass
        
        # SNS
        try:
            sns = session.client('sns', region_name=region)
            topics = sns.list_topics().get('Topics', [])
            counts['sns:topic'] = len(topics)
        except Exception as e:
            pass
        
        # SQS
        try:
            sqs = session.client('sqs', region_name=region)
            queues = sqs.list_queues().get('QueueUrls', [])
            counts['sqs:queue'] = len(queues)
        except Exception as e:
            pass
        
        return counts
    
    def count_resources_in_region(self, session, region):
        """Count all resources in a specific region"""
        all_counts = defaultdict(int)
        
        # Regional services
        regional_counters = [
            self.count_ec2_resources,
            self.count_rds_resources,
            self.count_lambda_resources,
            self.count_ecs_resources,
            self.count_eks_resources,
            self.count_ecr_resources,
            self.count_secrets_resources,
            self.count_kms_resources,
            self.count_cloudwatch_resources,
            self.count_elb_resources,
            self.count_other_resources,
        ]
        
        for counter in regional_counters:
            counts = counter(session, region)
            for key, value in counts.items():
                all_counts[key] += value
        
        return all_counts
    
    def count_account_resources(self, session, account_name, account_id):
        """Count all resources in an AWS account"""
        print(f"\nScanning AWS account: {account_name} ({account_id})")
        
        all_counts = defaultdict(int)
        
        # Get regions to scan
        scan_regions = self.config.get('regions', 'scan_regions', fallback='all')
        if scan_regions.lower() == 'all':
            regions = self.get_all_regions(session)
        else:
            regions = [r.strip() for r in scan_regions.split(',')]
        
        print(f"  Scanning {len(regions)} region(s)...")
        
        # Global services (only once)
        if self.cloud_config.getboolean('display', 'show_progress', fallback=True):
            print("  - Counting IAM resources (global)...")
        iam_counts = self.count_iam_resources(session)
        for key, value in iam_counts.items():
            all_counts[key] += value
        
        if self.cloud_config.getboolean('display', 'show_progress', fallback=True):
            print("  - Counting S3 resources (global)...")
        s3_counts = self.count_s3_resources(session)
        for key, value in s3_counts.items():
            all_counts[key] += value
        
        # Regional services
        for region in regions:
            if self.cloud_config.getboolean('display', 'show_progress', fallback=True):
                print(f"  - Scanning region: {region}...")
            
            region_counts = self.count_resources_in_region(session, region)
            for key, value in region_counts.items():
                all_counts[key] += value
        
        # Convert to standardized names
        standardized_counts = {}
        for key, value in all_counts.items():
            if value > 0:
                standard_name = self.RESOURCE_TYPE_MAPPING.get(key, key.upper().replace(':', '_'))
                if standard_name in standardized_counts:
                    standardized_counts[standard_name] += value
                else:
                    standardized_counts[standard_name] = value
        
        total_count = sum(standardized_counts.values())
        
        return {
            'account_name': account_name,
            'account_id': account_id,
            'total_count': total_count,
            'resource_types': standardized_counts
        }
    
    def scan_accounts(self):
        """Scan all configured AWS accounts"""
        print("=" * 80)
        print("AWS Asset Counter")
        print("=" * 80)
        
        # Get accounts from config or use current credentials
        if 'accounts' in self.config and len(self.config['accounts']) > 0:
            for account_name, account_value in self.config.items('accounts'):
                try:
                    # Determine if it's a profile, role ARN, or account ID
                    if account_value.startswith('arn:aws:iam::'):
                        session = self.get_session(role_arn=account_value)
                    else:
                        session = self.get_session(profile_name=account_value)
                    
                    if not session:
                        print(f"Skipping account {account_name}: Failed to create session")
                        continue
                    
                    account_id = self.get_account_id(session)
                    result = self.count_account_resources(session, account_name, account_id)
                    self.results['accounts'].append(result)
                    
                except Exception as e:
                    print(f"Error scanning account {account_name}: {e}")
        else:
            # Use default credentials
            try:
                profile = self.config.get('default', 'aws_profile', fallback=None)
                session = self.get_session(profile_name=profile)
                
                if not session:
                    print("Error: Failed to create session with default credentials")
                    return
                
                account_id = self.get_account_id(session)
                account_alias = self.get_account_alias(session)
                account_name = account_alias if account_alias else account_id
                
                result = self.count_account_resources(session, account_name, account_id)
                self.results['accounts'].append(result)
                
            except Exception as e:
                print(f"Error scanning default account: {e}")
    
    def display_results(self):
        """Display results to console"""
        print("\n" + "=" * 80)
        print("SCAN RESULTS")
        print("=" * 80)
        
        for account in self.results['accounts']:
            print(f"\nAWS:{account['account_name']} ({account['account_id']})")
            print(f"  Count: {account['total_count']}")
            
            if account['resource_types']:
                print("  Resource types:")
                
                # Sort by count if configured
                items = account['resource_types'].items()
                if self.cloud_config.getboolean('display', 'sort_by_count', fallback=True):
                    items = sorted(items, key=lambda x: x[1], reverse=True)
                else:
                    items = sorted(items)
                
                for resource_type, count in items:
                    print(f"    - {resource_type}: {count}")
    
    def save_json(self, output_file):
        """Save results to JSON file"""
        try:
            with open(output_file, 'w') as f:
                json.dump(self.results, f, indent=2)
            print(f"\nJSON results saved to: {output_file}")
        except Exception as e:
            print(f"Error saving JSON file: {e}")
    
    def save_csv(self, output_file):
        """Save results to CSV file"""
        try:
            with open(output_file, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['Provider', 'AccountName', 'AccountID', 'ResourceType', 'Count', 'ScanTimestamp'])
                
                for account in self.results['accounts']:
                    for resource_type, count in account['resource_types'].items():
                        writer.writerow([
                            self.results['provider'],
                            account['account_name'],
                            account['account_id'],
                            resource_type,
                            count,
                            self.results['scan_timestamp']
                        ])
            print(f"CSV results saved to: {output_file}")
        except Exception as e:
            print(f"Error saving CSV file: {e}")
    
    def run(self):
        """Main execution method"""
        # Scan accounts
        self.scan_accounts()
        
        # Display results
        self.display_results()
        
        # Prepare output directory
        output_dir = Path(self.cloud_config.get('output', 'output_dir', fallback='./output'))
        output_dir.mkdir(parents=True, exist_ok=True)
        
        # Prepare output filename
        prefix = self.cloud_config.get('output', 'output_prefix', fallback='aws_assets')
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
        description='AWS Asset Counter - Count all AWS resources',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python aws-asset-counter.py
  python aws-asset-counter.py --config my_aws_config.ini
  python aws-asset-counter.py --profile production
  python aws-asset-counter.py --output-prefix prod_assets
        """
    )
    
    parser.add_argument('--config', help='Path to AWS config file')
    parser.add_argument('--cloud-config', help='Path to cloud config file')
    parser.add_argument('--profile', help='AWS profile name to use')
    parser.add_argument('--output-prefix', help='Output file prefix')
    
    args = parser.parse_args()
    
    # Override config if provided
    config_file = args.config if args.config else 'aws_config.ini'
    cloud_config_file = args.cloud_config if args.cloud_config else 'cloud_config.ini'
    
    counter = AWSAssetCounter(config_file, cloud_config_file)
    
    # Override profile if provided
    if args.profile:
        counter.config['default']['aws_profile'] = args.profile
    
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







