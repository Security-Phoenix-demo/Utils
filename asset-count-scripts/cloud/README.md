# Cloud Asset Counter

A comprehensive suite of scripts to fetch, count, and inventory cloud resources across AWS, Azure, and GCP.

## 📋 Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Prerequisites](#prerequisites)
- [Installation](#installation)
- [Quick Start](#quick-start)
- [Configuration](#configuration)
- [Access Requirements](#access-requirements)
- [Usage](#usage)
- [Output Format](#output-format)
- [Troubleshooting](#troubleshooting)
- [Best Practices](#best-practices)

---

## Overview

These scripts provide automated cloud resource inventory across multiple cloud providers:
- **AWS Asset Counter** - Scans AWS accounts for EC2, S3, RDS, Lambda, ECS, EKS, and 30+ other services
- **Azure Asset Counter** - Scans Azure subscriptions using Resource Graph API
- **GCP Asset Counter** - Scans GCP projects using Cloud Asset Inventory API

Each script outputs:
- Console display with resource counts by type
- JSON file with structured data
- CSV file for spreadsheet analysis

## Features

✅ **Multi-Account Support** - Scan multiple accounts/subscriptions/projects in one run  
✅ **Comprehensive Coverage** - 50+ resource types per provider  
✅ **Flexible Authentication** - Multiple auth methods (profiles, service accounts, managed identity)  
✅ **Dual Output Format** - JSON and CSV exports  
✅ **Configurable** - Extensive configuration options  
✅ **Error Resilient** - Graceful handling of permission issues  
✅ **Standardized Names** - Consistent resource type naming across providers  

---

## Prerequisites

### Software Requirements
- **Python 3.8+** (3.9+ recommended)
- **pip** or **pipenv** for package management

### Cloud Access Requirements

#### AWS
- AWS CLI configured OR
- IAM credentials with read-only access OR
- IAM role for cross-account access

**Required Permissions**: See [AWS Access Requirements](#aws-access-requirements)

#### Azure
- Azure CLI installed and logged in (`az login`) OR
- Service Principal with Reader role OR
- Managed Identity (for Azure VMs)

**Required Permissions**: See [Azure Access Requirements](#azure-access-requirements)

#### GCP
- gcloud CLI configured (`gcloud auth application-default login`) OR
- Service Account key file with appropriate permissions

**Required Permissions**: See [GCP Access Requirements](#gcp-access-requirements)

---

## Installation

### Step 1: Clone or Download

```bash
cd Utils/asset-count-scripts/cloud
```

### Step 2: Install Dependencies

```bash
pip install -r requirements.txt
```

Or using specific provider dependencies:

```bash
# AWS only
pip install boto3 botocore

# Azure only
pip install azure-identity azure-mgmt-resource azure-mgmt-resourcegraph

# GCP only
pip install google-cloud-asset google-cloud-resource-manager google-auth
```

### Step 3: Configure Credentials

Copy the template configuration files:

```bash
# AWS
cp aws_config.ini.template aws_config.ini
# Edit aws_config.ini with your settings

# Azure
cp azure_config.ini.template azure_config.ini
# Edit azure_config.ini with your settings

# GCP
cp gcp_config.ini.template gcp_config.ini
# Edit gcp_config.ini with your settings
```

---

## Quick Start

### AWS

```bash
# Using AWS CLI default profile
python aws-asset-counter.py

# Using specific profile
python aws-asset-counter.py --profile production

# Using custom config
python aws-asset-counter.py --config my_aws_config.ini
```

### Azure

```bash
# Using Azure CLI credentials
python azure-asset-counter.py

# Scan specific subscription
python azure-asset-counter.py --subscription-id 12345678-1234-1234-1234-123456789012

# Using custom config
python azure-asset-counter.py --config my_azure_config.ini
```

### GCP

```bash
# Using Application Default Credentials
python gcp-asset-counter.py

# Scan specific project
python gcp-asset-counter.py --project-id my-project-123456

# Using custom config
python gcp-asset-counter.py --config my_gcp_config.ini
```

---

## Configuration

### Main Configuration File: `cloud_config.ini`

Controls output and display settings for all scripts:

```ini
[output]
output_prefix = cloud_assets          # File name prefix
output_dir = ./output                 # Output directory
include_timestamp = true              # Add timestamp to filename

[display]
show_progress = true                  # Show progress messages
verbose = false                       # Detailed logging
sort_by_count = true                  # Sort resources by count
```

### Provider-Specific Configuration

#### AWS Configuration: `aws_config.ini`

```ini
[default]
auth_method = profile                 # profile | keys | role
aws_profile = default                 # AWS CLI profile name
default_region = us-east-1

[accounts]
production = prod-profile             # Account name = profile/id/role ARN
development = dev-profile

[regions]
scan_regions = all                    # all | specific regions comma-separated
```

#### Azure Configuration: `azure_config.ini`

```ini
[default]
auth_method = cli                     # cli | service_principal | managed_identity

# For service principal:
# tenant_id = YOUR_TENANT_ID
# client_id = YOUR_CLIENT_ID
# client_secret = YOUR_CLIENT_SECRET

[subscriptions]
scan_mode = all                       # all | specific subscriptions below
# production = 12345678-1234-1234-1234-123456789012
```

#### GCP Configuration: `gcp_config.ini`

```ini
[default]
auth_method = adc                     # adc | service_account

# For service account:
# service_account_file = /path/to/key.json

[projects]
scan_mode = all                       # all | specific projects below
# production = my-prod-project-123456

[advanced]
use_asset_inventory = true            # Use Cloud Asset Inventory API
```

---

## Access Requirements

### AWS Access Requirements

#### Minimum IAM Policy (Read-Only)

The following IAM policy grants the minimum required permissions:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ec2:Describe*",
        "s3:ListAllMyBuckets",
        "s3:GetBucketLocation",
        "rds:Describe*",
        "lambda:List*",
        "lambda:Get*",
        "ecs:List*",
        "ecs:Describe*",
        "eks:List*",
        "eks:Describe*",
        "ecr:Describe*",
        "iam:List*",
        "iam:Get*",
        "secretsmanager:ListSecrets",
        "kms:ListKeys",
        "cloudwatch:DescribeAlarms",
        "elasticloadbalancing:Describe*",
        "route53:List*",
        "dynamodb:ListTables",
        "sns:ListTopics",
        "sqs:ListQueues",
        "sts:GetCallerIdentity"
      ],
      "Resource": "*"
    }
  ]
}
```

#### Setup Methods

**Option 1: AWS CLI Profile (Recommended for local use)**
```bash
aws configure --profile production
# Enter your access key, secret key, and region
```

**Option 2: IAM Role (Recommended for cross-account)**
1. Create IAM role in target account
2. Attach the read-only policy above
3. Configure trust relationship to allow assumption
4. Use role ARN in `aws_config.ini`

**Option 3: Environment Variables**
```bash
export AWS_ACCESS_KEY_ID=your_access_key
export AWS_SECRET_ACCESS_KEY=your_secret_key
export AWS_DEFAULT_REGION=us-east-1
```

#### CloudFormation Template

See `aws-iam-policy.yaml` for a ready-to-deploy CloudFormation template.

---

### Azure Access Requirements

#### Required Azure RBAC Role

**Built-in Role**: `Reader`

The Reader role provides read-only access to all resources in a subscription.

#### Required Permissions

For Resource Graph API (recommended):
- `Microsoft.ResourceGraph/resources/read`

For Resource Manager API (fallback):
- `Microsoft.Resources/subscriptions/read`
- `Microsoft.Resources/resources/read`

#### Setup Methods

**Option 1: Azure CLI (Recommended for local use)**
```bash
az login
# Follow browser authentication flow
```

**Option 2: Service Principal (Recommended for automation)**
```bash
# Create service principal
az ad sp create-for-rbac --name "AssetCounterSP" \
  --role "Reader" \
  --scopes /subscriptions/{subscription-id}

# Output provides: tenant_id, client_id, client_secret
# Add these to azure_config.ini
```

**Option 3: Managed Identity (For Azure VMs)**
```bash
# System-assigned identity is automatically configured
# Assign Reader role to the managed identity
az role assignment create \
  --assignee {managed-identity-principal-id} \
  --role "Reader" \
  --scope /subscriptions/{subscription-id}
```

#### ARM Template

See `azure-service-principal.json` for an ARM template to deploy service principal.

---

### GCP Access Requirements

#### Required IAM Roles

**Recommended Role**: `roles/cloudasset.viewer`

This provides access to Cloud Asset Inventory API.

#### Alternative Roles

If Asset Inventory is not available:
- `roles/viewer` - Basic viewer access
- `roles/browser` - Project browser access

#### Required Permissions

Minimum permissions needed:
```
cloudasset.assets.searchAllResources
resourcemanager.projects.get
resourcemanager.projects.list
```

#### Setup Methods

**Option 1: Application Default Credentials (Recommended for local use)**
```bash
gcloud auth application-default login
# Follow browser authentication flow
```

**Option 2: Service Account (Recommended for automation)**
```bash
# Create service account
gcloud iam service-accounts create asset-counter \
  --display-name="Asset Counter Service Account"

# Grant permissions
gcloud projects add-iam-policy-binding PROJECT_ID \
  --member="serviceAccount:asset-counter@PROJECT_ID.iam.gserviceaccount.com" \
  --role="roles/cloudasset.viewer"

# Create key file
gcloud iam service-accounts keys create key.json \
  --iam-account=asset-counter@PROJECT_ID.iam.gserviceaccount.com

# Use key file in gcp_config.ini
```

**Option 3: User Account**
```bash
gcloud auth login
# Follow browser authentication flow
```

#### Terraform Template

See `gcp-service-account.tf` for a Terraform template to deploy service account.

---

## Usage

### Command Line Options

#### AWS

```bash
python aws-asset-counter.py [OPTIONS]

Options:
  --config PATH              Path to AWS config file
  --cloud-config PATH        Path to cloud config file
  --profile NAME             AWS profile name to use
  --output-prefix PREFIX     Output file prefix
  -h, --help                Show help message
```

#### Azure

```bash
python azure-asset-counter.py [OPTIONS]

Options:
  --config PATH              Path to Azure config file
  --cloud-config PATH        Path to cloud config file
  --subscription-id ID       Azure subscription ID to scan
  --output-prefix PREFIX     Output file prefix
  -h, --help                Show help message
```

#### GCP

```bash
python gcp-asset-counter.py [OPTIONS]

Options:
  --config PATH              Path to GCP config file
  --cloud-config PATH        Path to cloud config file
  --project-id ID            GCP project ID to scan
  --output-prefix PREFIX     Output file prefix
  -h, --help                Show help message
```

### Examples

#### Scan Multiple AWS Accounts

Configure `aws_config.ini`:
```ini
[accounts]
production = arn:aws:iam::111111111111:role/AssetReaderRole
staging = arn:aws:iam::222222222222:role/AssetReaderRole
development = dev-profile
```

Run:
```bash
python aws-asset-counter.py
```

#### Scan All Azure Subscriptions

```bash
# Uses all subscriptions accessible by current credentials
python azure-asset-counter.py
```

#### Scan Specific GCP Projects

Configure `gcp_config.ini`:
```ini
[projects]
scan_mode = specific
production = my-prod-project-123
staging = my-staging-project-456
```

Run:
```bash
python gcp-asset-counter.py
```

#### Custom Output Location

```bash
python aws-asset-counter.py --output-prefix prod_inventory

# Creates files:
# ./output/prod_inventory_20251212_1430.json
# ./output/prod_inventory_20251212_1430.csv
```

---

## Output Format

### Console Output

```
================================================================================
AWS Asset Counter
================================================================================

Scanning AWS account: production (123456789012)
  Scanning 16 region(s)...
  - Counting IAM resources (global)...
  - Counting S3 resources (global)...
  - Scanning region: us-east-1...
  - Scanning region: us-west-2...
  ...

================================================================================
SCAN RESULTS
================================================================================

AWS:production (123456789012)
  Count: 8608
  Resource types:
    - POLICY_STATEMENT: 1237
    - SNAPSHOT: 942
    - VIRTUAL_MACHINE_IMAGE: 746
    - NETWORK_ADDRESS: 717
    - FIREWALL: 668
    - SECRET: 550
    ...

JSON results saved to: ./output/aws_assets_20251212_1430.json
CSV results saved to: ./output/aws_assets_20251212_1430.csv

================================================================================
Scan complete!
================================================================================
```

### JSON Output Format

```json
{
  "scan_timestamp": "2025-12-12T14:30:00Z",
  "provider": "AWS",
  "accounts": [
    {
      "account_name": "production",
      "account_id": "123456789012",
      "total_count": 8608,
      "resource_types": {
        "VIRTUAL_MACHINE": 150,
        "BUCKET": 45,
        "DATABASE": 12,
        ...
      }
    }
  ]
}
```

### CSV Output Format

```csv
Provider,AccountName,AccountID,ResourceType,Count,ScanTimestamp
AWS,production,123456789012,VIRTUAL_MACHINE,150,2025-12-12T14:30:00Z
AWS,production,123456789012,BUCKET,45,2025-12-12T14:30:00Z
AWS,production,123456789012,DATABASE,12,2025-12-12T14:30:00Z
...
```

---

## Troubleshooting

### Common Issues

#### AWS: "Unable to locate credentials"

**Solution**:
```bash
# Configure AWS CLI
aws configure

# Or set environment variables
export AWS_ACCESS_KEY_ID=your_key
export AWS_SECRET_ACCESS_KEY=your_secret
```

#### Azure: "No subscriptions found"

**Solution**:
```bash
# Login to Azure
az login

# List subscriptions
az account list

# Set default subscription
az account set --subscription "subscription-name"
```

#### GCP: "Could not automatically determine credentials"

**Solution**:
```bash
# Login with application default credentials
gcloud auth application-default login

# Or set service account key
export GOOGLE_APPLICATION_CREDENTIALS="/path/to/key.json"
```

#### Permission Denied Errors

**AWS**: Check IAM policy includes all required actions  
**Azure**: Ensure service principal has Reader role  
**GCP**: Verify cloudasset.viewer role is assigned  

#### Partial Results or Missing Resources

- Check region configuration (AWS)
- Verify resource filters are not excluding resources
- Ensure API quotas are not exceeded
- Check for service-specific permission issues

### Verbose Logging

Enable detailed logging in `cloud_config.ini`:

```ini
[display]
verbose = true
```

Or use verbose mode:
```bash
python aws-asset-counter.py 2>&1 | tee debug.log
```

---

## Best Practices

### Security

1. **Use Read-Only Access**: Grant minimum permissions (principle of least privilege)
2. **Rotate Credentials**: Regularly rotate access keys and service account keys
3. **Secure Config Files**: Protect configuration files with sensitive data
   ```bash
   chmod 600 aws_config.ini azure_config.ini gcp_config.ini
   ```
4. **Use Managed Identities**: Prefer managed identities over static credentials
5. **Audit Access**: Enable CloudTrail (AWS), Activity Log (Azure), Cloud Audit Logs (GCP)

### Performance

1. **Limit Regions**: Scan only necessary regions (AWS)
2. **Use Asset APIs**: Enable Asset Inventory (GCP) and Resource Graph (Azure)
3. **Parallel Processing**: Enable parallel processing for multiple accounts
4. **Schedule Off-Peak**: Run scans during off-peak hours

### Maintenance

1. **Regular Updates**: Keep scripts and dependencies updated
   ```bash
   pip install --upgrade -r requirements.txt
   ```
2. **Version Control**: Track configuration changes in version control (exclude credentials)
3. **Automated Scans**: Schedule regular scans via cron or CI/CD
4. **Alert on Changes**: Monitor significant changes in asset counts

### Data Management

1. **Archive Results**: Keep historical scan results for trend analysis
2. **Compare Scans**: Use CSV output to compare scans over time
3. **Integration**: Import CSV into dashboards, CMDB, or asset management tools
4. **Retention Policy**: Define retention period for scan results

---

## Advanced Usage

### Scanning Multiple Cloud Providers

```bash
# Run all three in parallel
python aws-asset-counter.py --output-prefix aws_scan &
python azure-asset-counter.py --output-prefix azure_scan &
python gcp-asset-counter.py --output-prefix gcp_scan &
wait

# Combine results
python combine-results.py aws_scan_*.json azure_scan_*.json gcp_scan_*.json
```

### Automated Daily Scans

```bash
# crontab entry (daily at 2 AM)
0 2 * * * cd /path/to/cloud && python aws-asset-counter.py --output-prefix daily_scan
```

### Integration with CMDB

```python
import pandas as pd

# Load CSV results
df = pd.read_csv('output/aws_assets_20251212_1430.csv')

# Process and upload to CMDB
# ... your CMDB integration code ...
```

---

## Support

For issues, questions, or contributions:
- Review the implementation plan: `IMPLEMENTATION_PLAN.md`
- Check access templates: `aws-iam-policy.yaml`, `azure-service-principal.json`, `gcp-service-account.tf`
- Refer to provider documentation:
  - [AWS IAM Documentation](https://docs.aws.amazon.com/IAM/)
  - [Azure RBAC Documentation](https://docs.microsoft.com/azure/role-based-access-control/)
  - [GCP IAM Documentation](https://cloud.google.com/iam/docs)

---

## License

Copyright © 2025. All rights reserved.

---

**Last Updated**: December 12, 2025  
**Version**: 1.0.0







